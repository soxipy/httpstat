package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/fatih/color"
)

const (
	httpsTemplate = `` +
		`  DNS Lookup   TCP Connection   TLS Handshake   Server Processing   Content Transfer` + "\n" +
		`[%s  | |   %s  | |  %s  | |      %s  | |     %s  ]` + "\n" +
		`            |                | |             | |                 | |                |` + "\n" +
		`   namelookup:%s      |               | |                 | |                |` + "\n" +
		`                       connect:%s     |                   | |                |` + "\n" +
		`                                   pretransfer:%s         |                  |` + "\n" +
		`                                                     starttransfer:%s        |` + "\n" +
		`                                                                                total:%s` + "\n"

	httpTemplate = `` +
		`   DNS Lookup   TCP Connection   Server Processing   Content Transfer` + "\n" +
		`[ %s  | |   %s  | |      %s  | |     %s  ]` + "\n" +
		`             |                | |                 | |                |` + "\n" +
		`    namelookup:%s      |                   | |                |` + "\n" +
		`                        connect:%s         |                  |` + "\n" +
		`                                      starttransfer:%s        |` + "\n" +
		`                                                                 total:%s` + "\n"
)

var (
	// Command line flags.
	httpMethod      string
	postBody        string
	followRedirects bool
	onlyHeader      bool
	insecure        bool
	httpHeaders     headers
	saveOutput      bool
	outputFile      string
	showVersion     bool
	clientCertFile  string
	fourOnly        bool
	sixOnly         bool
	verbose         bool

	// number of redirects followed
	redirectsFollowed int

	version = "devel" // for -v flag, updated during the release process with -ldflags=-X=main.version=...
)

const maxRedirects = 10

func init() {
	flag.StringVar(&httpMethod, "X", "GET", "HTTP method to use")
	flag.StringVar(&postBody, "d", "", "the body of a POST or PUT request; from file use @filename")
	flag.BoolVar(&followRedirects, "L", false, "follow 30x redirects")
	flag.BoolVar(&onlyHeader, "I", false, "don't read body of request")
	flag.BoolVar(&insecure, "k", false, "allow insecure SSL connections")
	flag.Var(&httpHeaders, "H", "set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'")
	flag.BoolVar(&saveOutput, "O", false, "save body as remote filename")
	flag.StringVar(&outputFile, "o", "", "output file for body")
	flag.BoolVar(&showVersion, "V", false, "print version number")
	flag.StringVar(&clientCertFile, "E", "", "client cert file for tls config")
	flag.BoolVar(&fourOnly, "4", false, "resolve IPv4 addresses only")
	flag.BoolVar(&sixOnly, "6", false, "resolve IPv6 addresses only")
	flag.BoolVar(&verbose, "v", false, "be verbose")

	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] URL1 URL2 @file1 URL3 @file2 ...\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "PARAMETERS:")
	fmt.Fprintln(os.Stderr, "Any number of URLs and filename references in @filename form in any combination")
	fmt.Fprintln(os.Stderr, "URLs in @file is a set of words delimited with whitespace characters, tabs and new lines.\n")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "ENVIRONMENT:")
	fmt.Fprintln(os.Stderr, "  HTTP_PROXY    proxy for HTTP requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "                used for HTTPS requests if HTTPS_PROXY undefined")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY   proxy for HTTPS requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "  NO_PROXY      comma-separated list of hosts to exclude from proxy")
}

func printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(color.Output, format, a...)
}

func grayscale(code color.Attribute) func(string, ...interface{}) string {
	return color.New(code + 232).SprintfFunc()
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("%s %s (runtime: %s)\n", os.Args[0], version, runtime.Version())
		os.Exit(0)
	}

	if fourOnly && sixOnly {
		fmt.Fprintf(os.Stderr, "%s: Only one of -4 and -6 may be specified\n", os.Args[0])
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	if (httpMethod == "POST" || httpMethod == "PUT") && postBody == "" {
		fmt.Fprintf(os.Stderr, "must supply post body using -d when POST or PUT is used\n")
		os.Exit(3)
	}

	if (saveOutput || outputFile != "") && len(args) > 1 {
		fmt.Fprintf(os.Stderr, "body saving is supported for single request only\n")
		os.Exit(4)
	}

	if onlyHeader {
		httpMethod = "HEAD"
	}

	for _, k := range args {
		if strings.HasPrefix(k, "@") {
			words, err := scanWords(k[1:])
			if err != nil {
				reportError(k, err)
				continue
			}
			for _, word := range words {
				parseAndVisit(word)
			}

		} else {
			parseAndVisit(k)
		}
	}
}

func reportError(url string, err error) {
	if verbose {
		printf("%s: ", url)
	} else {
		printf("%30s: ", url)
	}
	printf(color.RedString("ERROR: %v\n", err))
}

func parseAndVisit(arg string) {
	url, err := parseURL(arg)
	if err != nil {
		reportError(arg, err)
		return
	}
	visit(url)
}

func scanWords(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	var words []string
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}

	return words, nil
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := ioutil.ReadFile(clientCertFile)
	if err != nil {
		log.Fatalf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		log.Fatalf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}
}

func parseURL(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url, nil
}

func dialContext(network string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func visit(url *url.URL) {

	req, err := newRequest(httpMethod, url, postBody)
	if err != nil {
		reportError(url.String(), err)
		return
	}

	t0 := time.Now()
	t1, t2, t3, t4, t5, t6, t7, t8 := t0, t0, t0, t0, t0, t0, t0, t0
	var Err []error
	var ConnectTry int

	ctx, cancel := context.WithCancel(context.TODO())
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			t0 = time.Now()
			t1, t2, t3, t4, t5, t6, t7, t8 = t0, t0, t0, t0, t0, t0, t0, t0
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			t1 = time.Now()
			t2, t3, t4, t5, t6, t7, t8 = t1, t1, t1, t1, t1, t1, t1
		},
		// If net.Dialer.DualStack ("Happy Eyeballs") support is enabled,
		// this and the next hook may be called multiple times.
		// Need to track this with ConnectTry to cancel correctly.
		ConnectStart: func(_, _ string) {
			if ConnectTry == 0 {
				t2 = time.Now()
				t3, t4, t5, t6, t7, t8 = t2, t2, t2, t2, t2, t2
			}
			ConnectTry++
		},
		ConnectDone: func(net, addr string, err error) {
			ConnectTry--
			t3 = time.Now()
			t4, t5, t6, t7, t8 = t3, t3, t3, t3, t3

			if err != nil {
				Err = append(Err, err)
				if ConnectTry == 0 {
					cancel()
				}
			}

			if verbose {
				printf("\n%s%s\n", color.GreenString("Connected to "), color.CyanString(addr))
			}
		},
		TLSHandshakeStart: func() {
			t4 = time.Now()
			t6, t7, t8 = t4, t4, t4
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			t5 = time.Now()
			t6, t7, t8 = t5, t5, t5
		},
		GotConn: func(_ httptrace.GotConnInfo) {
			t6 = time.Now()
			t7, t8 = t6, t6
		},
		GotFirstResponseByte: func() {
			t7 = time.Now()
			t8 = t7
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 1 * time.Second,
	}

	switch {
	case fourOnly:
		tr.DialContext = dialContext("tcp4")
	case sixOnly:
		tr.DialContext = dialContext("tcp6")
	}

	switch url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			Certificates:       readClientCert(clientCertFile),
		}

		// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
		// See https://github.com/golang/go/issues/14275
		err = http2.ConfigureTransport(tr)
		if err != nil {
			Err = append(Err, err)
			cancel()
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
		Timeout: 3 * time.Second, // Overall request timeout with interrupting of reading of the Response.Body
	}

	var bodyMsg, Status string
	var ProtoMajor, ProtoMinor int
	resp, err := client.Do(req)
	if err != nil {
		Err = append(Err, err)
	} else {
		bodyMsg = readResponseBody(req, resp)
		ProtoMajor = resp.ProtoMajor
		ProtoMinor = resp.ProtoMinor
		Status = resp.Status
		resp.Body.Close()
	}

	t8 = time.Now() // after read body

	dnsLookup := t1.Sub(t0)
	tcpConnection := t3.Sub(t2)
	tlsHandshake := t5.Sub(t4)
	serverProcessing := t7.Sub(t6)
	contentTransfer := t8.Sub(t7)
	namelookup := t1.Sub(t0)
	connect := t3.Sub(t0)
	pretransfer := t6.Sub(t0)
	starttransfer := t7.Sub(t0)
	total := t8.Sub(t0)

	// print status line and headers
	if verbose {
		printf("\n%s%s%s\n", color.GreenString("HTTP"), grayscale(14)("/"), color.CyanString("%d.%d %s", ProtoMajor, ProtoMinor, Status))

		if resp != nil {
			names := make([]string, 0, len(resp.Header))
			for k := range resp.Header {
				names = append(names, k)
			}
			sort.Sort(headers(names))
			for _, k := range names {
				printf("%s %s\n", grayscale(14)(k+":"), color.CyanString(strings.Join(resp.Header[k], ",")))
			}

			if bodyMsg != "" {
				printf("\n%s\n", bodyMsg)
			}
		}

		fmta := func(d time.Duration) string {
			return color.CyanString("%7dms", int(d/time.Millisecond))
		}

		fmtb := func(d time.Duration) string {
			return color.CyanString("%-9s", strconv.Itoa(int(d/time.Millisecond))+"ms")
		}

		colorize := func(s string) string {
			v := strings.Split(s, "\n")
			v[0] = grayscale(16)(v[0])
			return strings.Join(v, "\n")
		}

		fmt.Println()

		switch url.Scheme {
		case "https":
			printf(colorize(httpsTemplate),
				fmta(dnsLookup),        // dns lookup
				fmta(tcpConnection),    // tcp connection
				fmta(tlsHandshake),     // tls handshake
				fmta(serverProcessing), // server processing
				fmta(contentTransfer),  // content transfer
				fmtb(namelookup),       // namelookup
				fmtb(connect),          // connect
				fmtb(pretransfer),      // pretransfer
				fmtb(starttransfer),    // starttransfer
				fmtb(total),            // total
			)
		case "http":
			printf(colorize(httpTemplate),
				fmta(dnsLookup),        // dns lookup
				fmta(tcpConnection),    // tcp connection
				fmta(serverProcessing), // server processing
				fmta(contentTransfer),  // content transfer
				fmtb(namelookup),       // namelookup
				fmtb(connect),          // connect
				fmtb(starttransfer),    // starttransfer
				fmtb(total),            // total
			)
		}

	} else {

		fmta := func(d time.Duration) string {
			return color.CyanString("%4d", int(d/time.Millisecond))
		}

		printf("%30s: %s %s %s %s %s %s",
			url.String(),
			fmta(dnsLookup),        // dns lookup
			fmta(tcpConnection),    // tcp connection
			fmta(tlsHandshake),     // tls handshake
			fmta(serverProcessing), // server processing
			fmta(contentTransfer),  // content transfer
			fmta(total),
		)
	}

	if Err != nil {
		printf(color.RedString("%sERROR: %v", func() string {
			if verbose {
				return ""
			}
			return " "
		}(), Err))
	}

	fmt.Println()

	if Err == nil && followRedirects && isRedirect(resp) {
		loc, err := resp.Location()
		if err != nil {
			Err = append(Err, err)
			cancel()
			return
		}

		if redirectsFollowed++; redirectsFollowed > maxRedirects {
			Err = append(Err, fmt.Errorf("maximum number of redirects (%d) followed", maxRedirects))
			cancel()
			return
		}

		visit(loc)
	}
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

func newRequest(method string, url *url.URL, body string) (*http.Request, error) {
	req, err := http.NewRequest(method, url.String(), createBody(body))
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %v", err)
	}
	for _, h := range httpHeaders {
		s := strings.Split(h, ":")
		k, v := strings.TrimRight(s[0], " "), strings.TrimLeft(s[1], " ")
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req, nil
}

func createBody(body string) io.Reader {
	if strings.HasPrefix(body, "@") {
		filename := body[1:]
		f, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open data file %s: %v\n", filename, err)
			os.Exit(5)
		}
		return f
	}
	return strings.NewReader(body)
}

// getFilenameFromHeaders tries to automatically determine the output filename,
// when saving to disk, based on the Content-Disposition header.
// If the header is not present, or it does not contain enough information to
// determine which filename to use, this function returns "".
func getFilenameFromHeaders(headers http.Header) string {
	// if the Content-Disposition header is set parse it
	if hdr := headers.Get("Content-Disposition"); hdr != "" {
		// pull the media type, and subsequent params, from
		// the body of the header field
		mt, params, err := mime.ParseMediaType(hdr)

		// if there was no error and the media type is attachment
		if err == nil && mt == "attachment" {
			if filename := params["filename"]; filename != "" {
				return filename
			}
		}
	}

	// return an empty string if we were unable to determine the filename
	return ""
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) string {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return ""
	}

	w := ioutil.Discard
	msg := color.CyanString("Body discarded")

	if saveOutput || outputFile != "" {
		filename := outputFile

		if saveOutput {
			// try to get the filename from the Content-Disposition header
			// otherwise fall back to the RequestURI
			if filename = getFilenameFromHeaders(resp.Header); filename == "" {
				filename = path.Base(req.URL.RequestURI())
			}

			if filename == "/" {
				fmt.Fprintf(os.Stderr, "no remote filename; specify output filename with -o to save response body\n")
				os.Exit(7)
			}
		}

		f, err := os.Create(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to create file %s: %v\n", filename, err)
			os.Exit(7)
		}
		defer f.Close()
		w = f
		msg = color.CyanString("Body read")
	}

	if _, err := io.Copy(w, resp.Body); err != nil && w != ioutil.Discard {
		fmt.Fprintf(os.Stderr, "failed to read response body: %v\n", err)
		os.Exit(7)
	}

	return msg
}

type headers []string

func (h headers) String() string {
	var o []string
	for _, v := range h {
		o = append(o, "-H "+v)
	}
	return strings.Join(o, " ")
}

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func (h headers) Len() int      { return len(h) }
func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h headers) Less(i, j int) bool {
	a, b := h[i], h[j]

	// server always sorts at the top
	if a == "Server" {
		return true
	}
	if b == "Server" {
		return false
	}

	endtoend := func(n string) bool {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
		switch n {
		case "Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade":
			return false
		default:
			return true
		}
	}

	x, y := endtoend(a), endtoend(b)
	if x == y {
		// both are of the same class
		return a < b
	}
	return x
}
