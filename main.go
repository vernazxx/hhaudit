package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
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

func scan(target *url.URL) {
	fmt.Printf("Scanning HTTP headers from: %s", target)
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
		log.Fatalln("Invalid URL")
	}

	scan(target)
}
