package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
)

// Set at build time via -ldflags "-X main.build=... -X main.commit=... -X main.date=...".
var (
	build  = "dev"
	commit = "none"
	date   = "unknown"
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

func versionString() string {
	return fmt.Sprintf("hhaudit %s (commit %s, built %s)", build, commit, date)
}

func scan(target *url.URL) (http.Header, error) {
	fmt.Printf("Target: %s\n\n", target.String())

	resp, err := http.Head(target.String())
	if err != nil {
		return nil, err
	}

	return resp.Header, nil
}

func getURL(rawurl *string) (*url.URL, error) {
	return url.ParseRequestURI(*rawurl)
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

func dumpHeaders(hd http.Header) {
	for h, v := range hd {
		fmt.Printf("%s: ", h)
		for vv := range v {
			fmt.Printf("%s", v[vv])
		}
		fmt.Println()
	}
}

func main() {
	printBanner()
	rawurl := flag.String("u", "http://example.com", "The URL of the target website to audit")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

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
	tgH, err = scan(target)
	if err != nil {
		slog.Error(err.Error(), "sys", "scan")
		os.Exit(1)
	}

	dumpHeaders(tgH)

	err = audit(kb, tgH)
	if err != nil {
		slog.Error(err.Error(), "sys", "audit")
		os.Exit(1)
	}
}
