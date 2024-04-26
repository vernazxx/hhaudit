package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
)

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

func scan(target *url.URL) error {
	fmt.Printf("Target: %s\n\n", target.String())

	req, err := http.NewRequest(http.MethodHead, target.String(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	for h, v := range resp.Header {
		for vv := range v {
			fmt.Printf("%s - %s\n", h, v[vv])
		}
	}
	return nil
}

func getURL(rawurl *string) (*url.URL, error) {
	return url.ParseRequestURI(*rawurl)
}

func main() {
	printBanner()
	rawurl := flag.String("u", "http://example.com", "The URL of the target website to audit")
	flag.Parse()

	target, err := getURL(rawurl)
	if err != nil {
		slog.Error("Input", err)
		os.Exit(1)
	}

	err = scan(target)
	if err != nil {
		slog.Error("Scan", err)
		os.Exit(1)
	}
}
