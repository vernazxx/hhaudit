package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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

// Exit codes: 0 every check passed, 1 the tool failed (bad input, network,
// output), 2 the audit completed and at least one check failed.
const (
	exitOK          = 0
	exitError       = 1
	exitAuditFailed = 2
)

const banner = `
 __     __                   __ __ __
|  |--.|  |--.---.-.--.--.--|  |__|  |_
|     ||     |  _  |  |  |  _  |  |   _|
|__|__||__|__|___._|_____|_____|__|____|

:: Audit those HTTP headers ::

`

func versionString() string {
	return fmt.Sprintf("hhaudit %s (commit %s, built %s)", build, commit, date)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI with args (without the program name) and returns the
// process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fail := func(err error, sys string) int {
		slog.Error(err.Error(), "sys", sys)
		return exitError
	}
	printf := func(format string, a ...any) error {
		_, err := fmt.Fprintf(stdout, format, a...)
		return err
	}

	fs := flag.NewFlagSet("hhaudit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rawurl := fs.String("u", "", "The URL of the target website to audit (required)")
	showVersion := fs.Bool("version", false, "Print version information and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		// The flag package has already printed the error and usage
		return exitError
	}
	// Parsing stops at the first non-flag argument; anything left over is a
	// mistake (e.g. a target without -u) and must not be silently ignored
	if fs.NArg() > 0 {
		fs.Usage()
		return fail(fmt.Errorf("unexpected arguments %q: pass the target with -u", fs.Args()), "input")
	}

	if *showVersion {
		if err := printf("%s\n", versionString()); err != nil {
			return fail(err, "output")
		}
		return exitOK
	}

	// No default target: auditing a site nobody asked for could pass a CI gate
	if *rawurl == "" {
		fs.Usage()
		return fail(errors.New("missing target: pass the URL to audit with -u"), "input")
	}

	if err := printf("%s", banner); err != nil {
		return fail(err, "output")
	}

	target, err := audit.ParseTarget(*rawurl)
	if err != nil {
		return fail(err, "input")
	}

	rules, err := audit.KnowledgeBase()
	if err != nil {
		return fail(err, "knowledge-base")
	}

	client, err := audit.NewClient(audit.DefaultTimeout, audit.DefaultMaxRedirects)
	if err != nil {
		return fail(err, "client")
	}

	if err := printf("Target: %s\n", audit.Sanitize(target.String())); err != nil {
		return fail(err, "output")
	}
	res, err := audit.Scan(context.Background(), client, target)
	if err != nil {
		return fail(err, "scan")
	}
	// Report the URL whose headers are actually being audited; it comes from
	// the server's redirects, so it is untrusted
	if err := printf("Final URL: %s\n\n", audit.Sanitize(res.Final.String())); err != nil {
		return fail(err, "output")
	}

	if err := audit.DumpHeaders(stdout, res.Header); err != nil {
		return fail(err, "output")
	}

	findings, err := audit.Audit(rules, res.Header)
	if err != nil {
		return fail(err, "audit")
	}
	if err := printf("\nAudit:\n"); err != nil {
		return fail(err, "output")
	}
	if err := audit.WriteReport(stdout, findings); err != nil {
		return fail(err, "output")
	}

	if audit.Failed(findings) {
		return exitAuditFailed
	}
	return exitOK
}
