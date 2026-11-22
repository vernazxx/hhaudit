package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	got := versionString()
	want := "hhaudit dev (commit none, built unknown)"

	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func server(t testing.TB, headers map[string]string) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func closedServer(t testing.TB) string {
	t.Helper()

	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	return srv.URL
}

func TestRun(t *testing.T) {
	compliant := map[string]string{"X-Content-Type-Options": "nosniff", "Content-Type": "text/html; charset=UTF-8"}

	cases := []struct {
		name     string
		args     []string
		want     int
		contains string
	}{
		{"all checks pass", []string{"-u", server(t, compliant)}, exitOK, "2 checks: 2 passed, 0 failed"},
		{"missing header", []string{"-u", server(t, map[string]string{"Content-Type": "text/html"})}, exitAuditFailed, "MISSING  X-Content-Type-Options"},
		{"value not allowed", []string{"-u", server(t, map[string]string{"X-Content-Type-Options": "sniff", "Content-Type": "text/html"})}, exitAuditFailed, "FAIL     X-Content-Type-Options: sniff"},
		{"empty Content-Type", []string{"-u", server(t, map[string]string{"X-Content-Type-Options": "nosniff", "Content-Type": ""})}, exitAuditFailed, "MISSING  Content-Type"},
		{"no target", nil, exitError, ""},
		{"empty target", []string{"-u", ""}, exitError, ""},
		{"target without -u", []string{"https://example.com"}, exitError, ""},
		{"extra argument after -u", []string{"-u", server(t, compliant), "https://intended.invalid"}, exitError, ""},
		{"flag after a stray argument", []string{"https://intended.invalid", "-u", server(t, compliant)}, exitError, ""},
		{"unsupported scheme", []string{"-u", "ftp://example.com"}, exitError, ""},
		{"unreachable target", []string{"-u", closedServer(t)}, exitError, ""},
		{"unknown flag", []string{"-nope"}, exitError, ""},
		{"help", []string{"-h"}, exitOK, ""},
		{"version", []string{"-version"}, exitOK, "hhaudit dev"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			got := run(tc.args, &stdout, io.Discard)
			if got != tc.want {
				t.Errorf("exit code %d want %d\noutput:\n%s", got, tc.want, stdout.String())
			}
			if !strings.Contains(stdout.String(), tc.contains) {
				t.Errorf("output does not contain %q:\n%s", tc.contains, stdout.String())
			}
		})
	}
}

func TestRunVersionSkipsBanner(t *testing.T) {
	var stdout bytes.Buffer
	run([]string{"-version"}, &stdout, io.Discard)
	if strings.Contains(stdout.String(), "Audit those HTTP headers") {
		t.Errorf("-version printed the banner:\n%s", stdout.String())
	}
}

func TestRunSanitizesFinalURL(t *testing.T) {
	// A redirect target is server-controlled; it must reach stdout sanitized
	target := server(t, map[string]string{"X-Content-Type-Options": "nosniff", "Content-Type": "text/html"})
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A raw Location header (http.Redirect would escape it): url.URL.String
		// keeps the raw query, so the override would survive to output
		w.Header().Set("Location", target+"/?q=a\u202eb")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	var stdout bytes.Buffer
	run([]string{"-u", redirect.URL}, &stdout, io.Discard)
	if strings.ContainsRune(stdout.String(), '\u202e') {
		t.Errorf("bidi override reached stdout:\n%q", stdout.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunOutputError(t *testing.T) {
	// A failing stdout (e.g. a closed pipe) is a tool error, not a pass
	compliant := map[string]string{"X-Content-Type-Options": "nosniff", "Content-Type": "text/html"}
	for _, args := range [][]string{{"-version"}, {"-u", server(t, compliant)}} {
		if got := run(args, failWriter{}, io.Discard); got != exitError {
			t.Errorf("run(%v) with failing stdout = %d want %d", args, got, exitError)
		}
	}
}
