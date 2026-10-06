package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	requestTimeout = 15 * time.Second
	maxRedirects   = 5
)

type Category int16

const (
	General  Category = 0
	Cache    Category = 1
	Security Category = 2
)

func (c Category) String() string {
	switch c {
	case General:
		return "general"
	case Cache:
		return "cache"
	case Security:
		return "security"
	}
	return "unknown"
}

type Header struct {
	Header   http.Header `json:"header"`
	Value    string      `json:"value"`
	Doc      string      `json:"doc"`
	Category string      `json:"category"`
	Rec      string      `json:"recommendation"`
}

func printBanner() {
	banner := `
 __     __                   __ __ __
|  |--.|  |--.---.-.--.--.--|  |__|  |_
|     ||     |  _  |  |  |  _  |  |   _|
|__|__||__|__|___._|_____|_____|__|____|

:: Audit those HTTP headers ::

`
	fmt.Printf("%s", banner)
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return checkScheme(req.URL)
		},
	}
}

func scan(client *http.Client, target *url.URL) (http.Header, error) {
	fmt.Printf("Target: %s\n", target.String())

	resp, err := client.Head(target.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Report the URL whose headers are actually being audited
	fmt.Printf("Final URL: %s\n\n", resp.Request.URL.String())

	return resp.Header, nil
}

func checkScheme(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", u.Scheme)
	}
	return nil
}

func getURL(rawurl *string) (*url.URL, error) {
	u, err := url.ParseRequestURI(*rawurl)
	if err != nil {
		return nil, err
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("URL has no host")
	}
	return u, nil
}

func audit(kb map[string]Header, tgH http.Header) error {
	// TODO: audit header values against a baseline db
	return nil
}

func populateData() (map[string]Header, error) {
	kb := map[string]Header{
		"Content-Type": {
			Doc:      "The `Content-Type` representation header is used to indicate the original media type of the resource (before any content encoding is applied for sending). If not set correctly, the resource (e.g. an image) may be interpreted as HTML, making XSS vulnerabilities possible.",
			Category: "general",
			Rec:      "",
		},
	}
	return kb, nil
}

// sanitize replaces control characters (including ANSI escape introducers)
// so untrusted header values cannot manipulate the terminal.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return unicode.ReplacementChar
		}
		return r
	}, s)
}

func dumpHeaders(w io.Writer, hd http.Header) error {
	names := make([]string, 0, len(hd))
	for h := range hd {
		names = append(names, h)
	}
	slices.Sort(names)

	for _, h := range names {
		if _, err := fmt.Fprintf(w, "%s: %s\n", sanitize(h), sanitize(strings.Join(hd[h], ", "))); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	printBanner()
	rawurl := flag.String("u", "http://example.com", "The URL of the target website to audit")
	flag.Parse()

	target, err := getURL(rawurl)
	if err != nil {
		slog.Error(err.Error(), "sys", "input")
		os.Exit(1)
	}

	kb, err := populateData()
	if err != nil {
		slog.Error(err.Error(), "sys", "knowledge-base")
		os.Exit(1)
	}

	var tgH http.Header
	tgH, err = scan(newClient(), target)
	if err != nil {
		slog.Error(err.Error(), "sys", "scan")
		os.Exit(1)
	}

	err = dumpHeaders(os.Stdout, tgH)
	if err != nil {
		slog.Error(err.Error(), "sys", "output")
		os.Exit(1)
	}

	err = audit(kb, tgH)
	if err != nil {
		slog.Error(err.Error(), "sys", "audit")
		os.Exit(1)
	}
}
