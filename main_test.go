package main

import (
	"testing"
)

func TestGetURL(t *testing.T) {
	rawurl := "http://example.com"
	_, err := getURL(&rawurl)

	assertError(t, err, nil)
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
