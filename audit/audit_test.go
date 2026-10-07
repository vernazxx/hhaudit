package audit_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/vernazxx/hhaudit/audit"
)

func TestParseTarget(t *testing.T) {
	cases := []string{
		"http://example.com",
		"https://example.com/path?q=1",
	}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			u, err := audit.ParseTarget(raw)
			assertError(t, err, nil)
			if u.String() != raw {
				t.Errorf("got %q want %q", u.String(), raw)
			}
		})
	}
}

func TestParseTargetRejectsInvalid(t *testing.T) {
	cases := []struct {
		raw  string
		want error // nil: any error is accepted
	}{
		{"file:///etc/passwd", audit.ErrUnsupportedScheme},
		{"ftp://example.com", audit.ErrUnsupportedScheme},
		{"gopher://example.com", audit.ErrUnsupportedScheme},
		{"http://", audit.ErrNoHost},
		{"example.com", nil},
		{"", nil},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			_, err := audit.ParseTarget(tc.raw)
			if err == nil {
				t.Fatalf("expected error for %q", tc.raw)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("got error %q want %q", err, tc.want)
			}
		})
	}
}

func TestCheckScheme(t *testing.T) {
	cases := []struct {
		name string
		u    *url.URL
		want error
	}{
		{"http", &url.URL{Scheme: "http"}, nil},
		{"https", &url.URL{Scheme: "https"}, nil},
		{"ftp", &url.URL{Scheme: "ftp"}, audit.ErrUnsupportedScheme},
		{"empty", &url.URL{}, audit.ErrUnsupportedScheme},
		{"nil", nil, audit.ErrNilTarget},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertErrorIs(t, audit.CheckScheme(tc.u), tc.want)
		})
	}
}

func TestNewClient(t *testing.T) {
	cases := []struct {
		name         string
		timeout      time.Duration
		maxRedirects int
		want         error
	}{
		{"defaults", audit.DefaultTimeout, audit.DefaultMaxRedirects, nil},
		{"no redirects", time.Second, 0, nil},
		{"zero timeout", 0, 5, audit.ErrInvalidOption},
		{"negative timeout", -time.Second, 5, audit.ErrInvalidOption},
		{"negative redirects", time.Second, -1, audit.ErrInvalidOption},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := audit.NewClient(tc.timeout, tc.maxRedirects)
			assertErrorIs(t, err, tc.want)
			if tc.want == nil && c.Timeout != tc.timeout {
				t.Errorf("got timeout %s want %s", c.Timeout, tc.timeout)
			}
		})
	}
}

func TestScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("got method %s want HEAD", r.Method)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()

	target := mustParse(t, srv.URL)
	res, err := audit.Scan(context.Background(), newClient(t), target)

	assertError(t, err, nil)
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("got %q want %q", got, "nosniff")
	}
	if res.Requested != target {
		t.Errorf("got requested %v want %v", res.Requested, target)
	}
	if res.Final.String() != srv.URL {
		t.Errorf("got final %q want %q", res.Final, srv.URL)
	}
}

func TestScanReportsFinalURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
		}
	}))
	defer srv.Close()

	res, err := audit.Scan(context.Background(), newClient(t), mustParse(t, srv.URL))

	assertError(t, err, nil)
	if want := srv.URL + "/final"; res.Final.String() != want {
		t.Errorf("got final %q want %q", res.Final, want)
	}
}

func TestScanRejectsInvalidInput(t *testing.T) {
	client := newClient(t)
	cases := []struct {
		name   string
		client *http.Client
		target *url.URL
		want   error
	}{
		{"nil client", nil, mustParse(t, "http://example.com"), audit.ErrNilClient},
		{"nil target", client, nil, audit.ErrNilTarget},
		{"ftp target", client, &url.URL{Scheme: "ftp", Host: "example.com"}, audit.ErrUnsupportedScheme},
		{"no host", client, &url.URL{Scheme: "http"}, audit.ErrNoHost},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := audit.Scan(context.Background(), tc.client, tc.target)
			assertErrorIs(t, err, tc.want)
		})
	}
}

func TestScanCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := audit.Scan(ctx, newClient(t), mustParse(t, srv.URL))
	assertErrorIs(t, err, context.Canceled)
}

func TestScanTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	client, err := audit.NewClient(50*time.Millisecond, audit.DefaultMaxRedirects)
	assertError(t, err, nil)

	if _, err := audit.Scan(context.Background(), client, mustParse(t, srv.URL)); err == nil {
		t.Error("expected timeout error")
	}
}

func TestScanRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := audit.Scan(context.Background(), newClient(t), mustParse(t, srv.URL)); err == nil {
		t.Error("expected redirect limit error")
	}
}

func TestScanRejectsRedirectToOtherScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/", http.StatusFound)
	}))
	defer srv.Close()

	_, err := audit.Scan(context.Background(), newClient(t), mustParse(t, srv.URL))
	assertErrorIs(t, err, audit.ErrUnsupportedScheme)
}

func TestDumpHeaders(t *testing.T) {
	hd := http.Header{
		"X-Frame-Options": {"DENY"},
		"Cache-Control":   {"no-store", "max-age=0"},
		"X-Evil":          {"a\x1b[2Jb"},
	}

	var buf bytes.Buffer
	err := audit.DumpHeaders(&buf, hd)

	assertError(t, err, nil)

	want := "Cache-Control: no-store, max-age=0\n" +
		"X-Evil: a�[2Jb\n" +
		"X-Frame-Options: DENY\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestDumpHeadersNilWriter(t *testing.T) {
	err := audit.DumpHeaders(nil, http.Header{"X-Frame-Options": {"DENY"}})
	assertErrorIs(t, err, audit.ErrNilWriter)
}

func TestSanitize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain value", "plain value"},
		{"a\x1b[31mb", "a�[31mb"},
		{"line\r\nbreak", "line��break"},
		{"nul\x00", "nul�"},
		{"", ""},
	}

	for _, tc := range cases {
		if got := audit.Sanitize(tc.in); got != tc.want {
			t.Errorf("Sanitize(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestKnowledgeBase(t *testing.T) {
	kb, err := audit.KnowledgeBase()

	assertError(t, err, nil)
	if len(kb) == 0 {
		t.Fatal("knowledge base is empty")
	}
	categories := []string{audit.General.String(), audit.Cache.String(), audit.Security.String()}
	for name, h := range kb {
		if h.Doc == "" {
			t.Errorf("%s: empty Doc", name)
		}
		valid := false
		for _, c := range categories {
			valid = valid || h.Category == c
		}
		if !valid {
			t.Errorf("%s: invalid category %q", name, h.Category)
		}
	}
}

func TestCategoryString(t *testing.T) {
	cases := []struct {
		c    audit.Category
		want string
	}{
		{audit.General, "general"},
		{audit.Cache, "cache"},
		{audit.Security, "security"},
		{audit.Category(99), "unknown"},
	}

	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}

func newClient(t testing.TB) *http.Client {
	t.Helper()

	c, err := audit.NewClient(audit.DefaultTimeout, audit.DefaultMaxRedirects)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustParse(t testing.TB, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func assertError(t testing.TB, got, want error) {
	t.Helper()

	if got != want {
		t.Errorf("got error %q want error %q", got, want)
	}
}

func assertErrorIs(t testing.TB, got, want error) {
	t.Helper()

	if want == nil {
		assertError(t, got, nil)
		return
	}
	if !errors.Is(got, want) {
		t.Errorf("got error %v want error %v", got, want)
	}
}
