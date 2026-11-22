// Package audit fetches the HTTP response headers of a target URL and audits
// them against a baseline knowledge base.
package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultTimeout      = 15 * time.Second
	DefaultMaxRedirects = 5
)

var (
	ErrUnsupportedScheme = errors.New("unsupported URL scheme: only http and https are allowed")
	ErrNoHost            = errors.New("URL has no host")
	ErrNilClient         = errors.New("nil HTTP client")
	ErrNilTarget         = errors.New("nil target URL")
	ErrNilWriter         = errors.New("nil writer")
	ErrInvalidOption     = errors.New("invalid option")
)

// Result holds the headers returned for a scanned target.
type Result struct {
	// Requested is the URL the scan started from.
	Requested *url.URL
	// Final is the URL whose headers were returned, after following redirects.
	Final  *url.URL
	Header http.Header
}

// CheckScheme returns an error unless u uses the http or https scheme.
func CheckScheme(u *url.URL) error {
	if u == nil {
		return ErrNilTarget
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: got %q", ErrUnsupportedScheme, u.Scheme)
	}
	return nil
}

func validateTarget(u *url.URL) error {
	if err := CheckScheme(u); err != nil {
		return err
	}
	if u.Host == "" {
		return ErrNoHost
	}
	return nil
}

// ParseTarget parses raw as an absolute http(s) URL with a host.
func ParseTarget(raw string) (*url.URL, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, err
	}
	if err := validateTarget(u); err != nil {
		return nil, err
	}
	return u, nil
}

// NewClient returns an HTTP client with the given overall request timeout
// that follows at most maxRedirects redirects, and only to http(s) URLs.
func NewClient(timeout time.Duration, maxRedirects int) (*http.Client, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("%w: timeout must be positive, got %s", ErrInvalidOption, timeout)
	}
	if maxRedirects < 0 {
		return nil, fmt.Errorf("%w: maxRedirects must not be negative, got %d", ErrInvalidOption, maxRedirects)
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return CheckScheme(req.URL)
		},
	}, nil
}

// Scan sends a HEAD request to target and returns the response headers
// together with the final URL they were served from.
func Scan(ctx context.Context, client *http.Client, target *url.URL) (*Result, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	return &Result{
		Requested: target,
		Final:     resp.Request.URL,
		Header:    resp.Header,
	}, nil
}

// Status is the outcome of checking one rule against a response.
type Status int16

const (
	// Pass: the header matches the rule.
	Pass Status = iota
	// Fail: the header is sent, but with a value the rule doesn't allow.
	Fail
	// Missing: a present rule's header isn't sent.
	Missing
	// Unwanted: an absent rule's header is sent.
	Unwanted
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Fail:
		return "FAIL"
	case Missing:
		return "MISSING"
	case Unwanted:
		return "REMOVE"
	}
	return "UNKNOWN"
}

// Finding is the result of one rule. Got holds the values the target sent,
// unsanitized; print them only through Sanitize or WriteReport.
type Finding struct {
	Rule   Rule
	Status Status
	Got    []string
}

// Audit checks the target headers against the rules and returns one finding
// per rule, in the order of rules. It returns an error, never an empty
// passing result, when there are no rules.
func Audit(rules []Rule, h http.Header) ([]Finding, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("%w: no rules", ErrInvalidBaseline)
	}

	findings := make([]Finding, 0, len(rules))
	for _, rule := range rules {
		got := h.Values(rule.Name)
		findings = append(findings, Finding{Rule: rule, Status: check(rule, got), Got: got})
	}
	return findings, nil
}

func check(rule Rule, got []string) Status {
	if rule.Expect == Absent {
		if len(got) > 0 {
			return Unwanted
		}
		return Pass
	}

	// An empty value is as good as not sending the header (e.g. an empty
	// Content-Type lets the browser sniff)
	sent := slices.DeleteFunc(slices.Clone(got), func(v string) bool { return strings.TrimSpace(v) == "" })
	if len(sent) == 0 {
		return Missing
	}
	if len(rule.Allowed) == 0 {
		return Pass
	}
	for _, v := range got {
		if !containsFold(rule.Allowed, strings.TrimSpace(v)) {
			return Fail
		}
	}
	return Pass
}

// Failed reports whether any finding is not a pass.
func Failed(findings []Finding) bool {
	return slices.ContainsFunc(findings, func(f Finding) bool { return f.Status != Pass })
}

// WriteReport writes one line per finding to w, with the recommendation and
// source under each finding that didn't pass, and a summary line. Every value
// is sanitized.
func WriteReport(w io.Writer, findings []Finding) error {
	if w == nil {
		return ErrNilWriter
	}

	failed := 0
	for _, f := range findings {
		line := Sanitize(f.Rule.Name)
		if len(f.Got) > 0 {
			line += ": " + Sanitize(strings.Join(f.Got, ", "))
		}
		if _, err := fmt.Fprintf(w, "%-8s %s\n", f.Status, line); err != nil {
			return err
		}
		if f.Status == Pass {
			continue
		}
		failed++

		if _, err := fmt.Fprintf(w, "%-8s recommended: %s\n", "", advice(f.Rule)); err != nil {
			return err
		}
		if len(f.Rule.Sources) > 0 {
			if _, err := fmt.Fprintf(w, "%-8s see: %s\n", "", Sanitize(f.Rule.Sources[0])); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintf(w, "\n%d checks: %d passed, %d failed\n", len(findings), len(findings)-failed, failed)
	return err
}

// removeAdvice is the recommendation for a header an absent rule finds.
const removeAdvice = "remove this header"

// advice returns the sanitized recommendation for a rule that didn't pass:
// the header to set for a present rule, removeAdvice otherwise.
func advice(rule Rule) string {
	if rule.Expect == Present {
		return Sanitize(rule.Name) + ": " + Sanitize(rule.Recommended)
	}
	return removeAdvice
}

// unsafeRune reports whether r must not reach a terminal: control characters
// (including ANSI escape introducers) and Unicode format characters (bidi
// overrides and isolates, zero-width characters).
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// Sanitize replaces control characters (including ANSI escape introducers)
// and Unicode format characters (bidi overrides and isolates, zero-width
// characters) so untrusted header values cannot manipulate or visually spoof
// the terminal.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return unicode.ReplacementChar
		}
		return r
	}, s)
}

// DumpHeaders writes hd to w sorted by name, one sanitized header per line.
func DumpHeaders(w io.Writer, hd http.Header) error {
	if w == nil {
		return ErrNilWriter
	}

	names := make([]string, 0, len(hd))
	for h := range hd {
		names = append(names, h)
	}
	slices.Sort(names)

	for _, h := range names {
		if _, err := fmt.Fprintf(w, "%s: %s\n", Sanitize(h), Sanitize(strings.Join(hd[h], ", "))); err != nil {
			return err
		}
	}
	return nil
}
