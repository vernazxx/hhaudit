package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	rules, err := audit.KnowledgeBase()
	assertError(t, err, nil)

	byName := map[string]audit.Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	xcto, ok := byName["X-Content-Type-Options"]
	if !ok {
		t.Fatal("embedded baseline has no X-Content-Type-Options rule")
	}
	if xcto.Expect != audit.Present || xcto.Recommended != "nosniff" || len(xcto.Allowed) != 1 || xcto.Allowed[0] != "nosniff" {
		t.Errorf("X-Content-Type-Options rule = %+v, want present, allowed and recommended nosniff", xcto)
	}
	if xcto.Category != audit.Security {
		t.Errorf("X-Content-Type-Options category = %s want security", xcto.Category)
	}
	for _, r := range rules {
		for _, s := range r.Sources {
			if !strings.HasPrefix(s, "https://") {
				t.Errorf("%s: source %q is not https", r.Name, s)
			}
		}
	}
}

// ruleJSON returns a valid present rule as JSON, with fields overridden by extra.
func ruleJSON(t testing.TB, extra map[string]any) string {
	t.Helper()

	r := map[string]any{
		"name":        "X-Test",
		"category":    "security",
		"expect":      "present",
		"allowed":     []string{"on"},
		"recommended": "on",
		"doc":         "Test header.",
		"sources":     []string{"https://example.com/doc"},
	}
	for k, v := range extra {
		if v == nil {
			delete(r, k)
			continue
		}
		r[k] = v
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func doc(rules ...string) string {
	return `{"rules": [` + strings.Join(rules, ",") + `]}`
}

func TestLoadRules(t *testing.T) {
	absent := ruleJSON(t, map[string]any{"name": "Server", "expect": "absent", "allowed": nil, "recommended": nil})
	rules, err := audit.LoadRules(strings.NewReader(doc(ruleJSON(t, nil), absent)))
	assertError(t, err, nil)

	if len(rules) != 2 {
		t.Fatalf("got %d rules want 2", len(rules))
	}
	// Sorted by name
	if rules[0].Name != "Server" || rules[1].Name != "X-Test" {
		t.Errorf("rules not sorted by name: %s, %s", rules[0].Name, rules[1].Name)
	}
	if rules[0].Expect != audit.Absent || rules[1].Expect != audit.Present {
		t.Errorf("expectations = %s, %s want absent, present", rules[0].Expect, rules[1].Expect)
	}
	if rules[1].Category != audit.Security {
		t.Errorf("category = %s want security", rules[1].Category)
	}

	// Allowed may be omitted: any value is accepted
	_, err = audit.LoadRules(strings.NewReader(doc(ruleJSON(t, map[string]any{"allowed": nil}))))
	assertError(t, err, nil)
}

func TestLoadRulesRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"not json", "nope"},
		{"empty rules", `{"rules": []}`},
		{"no rules key", `{}`},
		{"unknown top-level field", `{"rules": [], "extra": 1}`},
		{"unknown rule field", doc(ruleJSON(t, map[string]any{"severity": "high"}))},
		{"trailing data", doc(ruleJSON(t, nil)) + `{}`},
		{"unknown category", doc(ruleJSON(t, map[string]any{"category": "fun"}))},
		{"unknown expectation", doc(ruleJSON(t, map[string]any{"expect": "maybe"}))},
		{"missing name", doc(ruleJSON(t, map[string]any{"name": nil}))},
		{"non-canonical name", doc(ruleJSON(t, map[string]any{"name": "x-test"}))},
		{"name with space", doc(ruleJSON(t, map[string]any{"name": "X Test"}))},
		{"name with control character", doc(ruleJSON(t, map[string]any{"name": "X-Test\u001b"}))},
		{"duplicate name", doc(ruleJSON(t, nil), ruleJSON(t, nil))},
		{"empty doc", doc(ruleJSON(t, map[string]any{"doc": " "}))},
		{"no sources", doc(ruleJSON(t, map[string]any{"sources": []string{}}))},
		{"http source", doc(ruleJSON(t, map[string]any{"sources": []string{"http://example.com/doc"}}))},
		{"source without host", doc(ruleJSON(t, map[string]any{"sources": []string{"https:///doc"}}))},
		{"present without recommended", doc(ruleJSON(t, map[string]any{"recommended": nil}))},
		{"recommended not allowed", doc(ruleJSON(t, map[string]any{"recommended": "off"}))},
		{"absent with recommended", doc(ruleJSON(t, map[string]any{"expect": "absent", "allowed": nil}))},
		{"absent with allowed", doc(ruleJSON(t, map[string]any{"expect": "absent", "recommended": nil}))},
		{"too large", doc(ruleJSON(t, map[string]any{"doc": strings.Repeat("a", audit.MaxBaselineSize)}))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := audit.LoadRules(strings.NewReader(tc.in))
			assertErrorIs(t, err, audit.ErrInvalidBaseline)
		})
	}

	t.Run("nil reader", func(t *testing.T) {
		_, err := audit.LoadRules(nil)
		assertErrorIs(t, err, audit.ErrInvalidBaseline)
	})
}

func TestTextRoundTrip(t *testing.T) {
	for _, c := range []audit.Category{audit.General, audit.Cache, audit.Security} {
		b, err := c.MarshalText()
		assertError(t, err, nil)
		var got audit.Category
		assertError(t, got.UnmarshalText(b), nil)
		if got != c {
			t.Errorf("category round trip: got %s want %s", got, c)
		}
	}
	for _, e := range []audit.Expectation{audit.Present, audit.Absent} {
		b, err := e.MarshalText()
		assertError(t, err, nil)
		var got audit.Expectation
		assertError(t, got.UnmarshalText(b), nil)
		if got != e {
			t.Errorf("expectation round trip: got %s want %s", got, e)
		}
	}

	if _, err := audit.Category(99).MarshalText(); err == nil {
		t.Error("unknown category marshalled without error")
	}
	if _, err := audit.Expectation(99).MarshalText(); err == nil {
		t.Error("unknown expectation marshalled without error")
	}
	var c audit.Category
	if err := c.UnmarshalText([]byte("fun")); err == nil {
		t.Error("unknown category unmarshalled without error")
	}
	var e audit.Expectation
	if err := e.UnmarshalText([]byte("maybe")); err == nil {
		t.Error("unknown expectation unmarshalled without error")
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
