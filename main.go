package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/vernazxx/hhaudit/audit"
)

// Set at build time via -ldflags "-X main.build=... -X main.commit=... -X main.date=...".
var (
	build  = "dev"
	commit = "none"
	date   = "unknown"
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

func versionString() string {
	return fmt.Sprintf("hhaudit %s (commit %s, built %s)", build, commit, date)
}

func fatal(err error, sys string) {
	slog.Error(err.Error(), "sys", sys)
	os.Exit(1)
}

func main() {
	rawurl := flag.String("u", "http://example.com", "The URL of the target website to audit")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	printBanner()

	target, err := audit.ParseTarget(*rawurl)
	if err != nil {
		fatal(err, "input")
	}

	kb, err := audit.KnowledgeBase()
	if err != nil {
		fatal(err, "knowledge-base")
	}

	client, err := audit.NewClient(audit.DefaultTimeout, audit.DefaultMaxRedirects)
	if err != nil {
		fatal(err, "client")
	}

	fmt.Printf("Target: %s\n", target.String())
	res, err := audit.Scan(context.Background(), client, target)
	if err != nil {
		fatal(err, "scan")
	}
	// Report the URL whose headers are actually being audited
	fmt.Printf("Final URL: %s\n\n", res.Final.String())

	if err := audit.DumpHeaders(os.Stdout, res.Header); err != nil {
		fatal(err, "output")
	}

	if err := audit.Audit(kb, res.Header); err != nil {
		fatal(err, "audit")
	}
}
