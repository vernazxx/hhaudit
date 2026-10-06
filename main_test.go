package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGetURL(t *testing.T) {
	rawurl := "http://example.com"
	_, err := getURL(&rawurl)

	assertError(t, err, nil)
}

func TestGetURLRejectsInvalid(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com",
		"gopher://example.com",
		"http://",
		"example.com",
		"",
	}

	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := getURL(&raw); err == nil {
				t.Errorf("expected error for %q", raw)
			}
		})
	}
}

func TestScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	hd, err := scan(newClient(), target)

	assertError(t, err, nil)
	if got := hd.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("got %q want %q", got, "nosniff")
	}
}

func TestScanTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	client := newClient()
	client.Timeout = 50 * time.Millisecond
	target, _ := url.Parse(srv.URL)

	if _, err := scan(client, target); err == nil {
		t.Error("expected timeout error")
	}
}

func TestScanRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)

	if _, err := scan(newClient(), target); err == nil {
		t.Error("expected redirect limit error")
	}
}

func TestScanRejectsRedirectToOtherScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/", http.StatusFound)
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)

	if _, err := scan(newClient(), target); err == nil {
		t.Error("expected error for redirect to ftp")
	}
}

func TestDumpHeaders(t *testing.T) {
	hd := http.Header{
		"X-Frame-Options": {"DENY"},
		"Cache-Control":   {"no-store", "max-age=0"},
		"X-Evil":          {"a\x1b[2Jb"},
	}

	var buf bytes.Buffer
	err := dumpHeaders(&buf, hd)

	assertError(t, err, nil)

	want := "Cache-Control: no-store, max-age=0\n" +
		"X-Evil: a\uFFFD[2Jb\n" +
		"X-Frame-Options: DENY\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestVersionString(t *testing.T) {
	got := versionString()
	want := "hhaudit dev (commit none, built unknown)"

	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func assertError(t testing.TB, got, want error) {
	t.Helper()

	if got != want {
		t.Errorf("got error %q want error %q", got, want)
	}
}
