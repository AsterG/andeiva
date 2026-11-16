package main

import (
	"fmt"
	"testing"
	"time"
)

func TestReleaseTime(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	good := func(suite string, date, until time.Time) []byte {
		return []byte(fmt.Sprintf("Codename: %s\nDate: %s\nValid-Until: %s\nSHA256:\n aabb 1 main/source/Sources\n", suite, date.Format(time.RFC1123Z), until.Format(time.RFC1123Z)))
	}
	for _, suite := range []string{"trixie", "trixie-security", "trixie-updates"} {
		if releaseTime(good(suite, now.Add(-time.Hour), now.Add(time.Hour)), now) != nil {
			t.Fatal(suite)
		}
	}
	for _, bad := range [][]byte{good("other", now, now.Add(time.Hour)), good("trixie-security", now.Add(-2*time.Hour), now.Add(-time.Hour)), good("trixie", now.Add(time.Hour), now.Add(2*time.Hour)), []byte("Codename: trixie-security\nDate: bad\n"), []byte("Codename: trixie\nCodename: trixie\n")} {
		if releaseTime(bad, now) == nil {
			t.Fatal("untrusted/stale release accepted")
		}
	}
}
func TestEmptyAndDuplicateControlFields(t *testing.T) {
	if _, e := parseControl([]byte("Package: p\nConffiles:\n\n")); e != nil {
		t.Fatal(e)
	}
	if _, e := parseControl([]byte("Conffiles:\nConffiles:\n")); e == nil {
		t.Fatal("duplicate empty field")
	}
}
