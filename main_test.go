package main

import "testing"

func TestVersionString(t *testing.T) {
	got := versionString()
	want := "hhaudit dev (commit none, built unknown)"

	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
