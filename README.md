# httpstat [![Build Status](https://api.travis-ci.org/soxipy/httpstat.svg?branch=master)](https://travis-ci.org/soxipy/httpstat)

Many thanks to Dave Cheney and to all who contribute!

It is under heavy reconstruction now, come in a week or two to look at complete version and release

![httpstat screenshot](./screenshot.png)

## Installation

`httpstat` requires Go 1.11 or later.

```sh
go get github.com/soxipy/httpstat
```

## Usage

```sh
httpstat example.com [another.url ...]
```

## Features

- MacOS/Windows/BSD/Linux supported.
- HTTP and HTTPS are supported, for self signed certificates use `-k`.
- Skip timing the body of a response with `-I`.
- Follow 30x redirects with `-L`.
- Change HTTP method with `-X METHOD`.
- Provide a `PUT` or `POST` request body with `-d string`. To supply the `PUT` or `POST` body as a file, use `-d @filename`.
- Add extra request headers with `-H 'Name: value'`.
- The response body is usually discarded, you can use `-o filename` to save it to a file, or `-O` to save it to the file name suggested by the server.
- HTTP/HTTPS proxies supported via the usual `HTTP_PROXY`/`HTTPS_PROXY` env vars (as well as lower case variants).
- Supply your own client side certificate with `-E cert.pem`.
