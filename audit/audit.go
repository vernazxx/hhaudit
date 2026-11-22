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

// Audit checks the target headers against the knowledge base rules.
func Audit(rules []Rule, tgH http.Header) error {
	// TODO: audit header values against a baseline db
	return nil
}

// Sanitize replaces control characters (including ANSI escape introducers)
// and Unicode format characters (bidi overrides and isolates, zero-width
// characters) so untrusted header values cannot manipulate or visually spoof
// the terminal.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
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
