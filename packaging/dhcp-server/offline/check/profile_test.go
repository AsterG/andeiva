package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func goodPlan() string {
	s := "VERSION 3\nAPT::Architecture=amd64\n\n"
	for _, a := range archives() {
		s += fmt.Sprintf("%s - - none < %s %s none /stage/archives/%s\n", a.Name, a.Version, a.Arch, a.Leaf())
	}
	for _, a := range archives() {
		s += fmt.Sprintf("%s - - none < %s %s none **CONFIGURE**\n", a.Name, a.Version, a.Arch)
	}
	return s
}
func TestLockedPlan(t *testing.T) {
	good := goodPlan()
	if e := validatePlan(strings.NewReader(good), "/stage/archives"); e != nil {
		t.Fatal(e)
	}
	cases := map[string]string{
		"downgrade":          strings.Replace(good, " < ", " > ", 1),
		"existing":           strings.Replace(good, "- - none <", "1.0 amd64 none <", 1),
		"remove":             strings.Replace(good, "**CONFIGURE**", "**REMOVE**", 1),
		"wrong architecture": strings.Replace(good, "amd64 none /stage", "arm64 none /stage", 1),
		"foreign filename":   strings.Replace(good, "/stage/archives/", "/tmp/", 1),
		"missing configure":  strings.TrimSuffix(good, strings.Split(strings.TrimSuffix(good, "\n"), "\n")[22]+"\n"),
		"missing unpack":     strings.Replace(good, strings.Split(good, "\n")[3]+"\n", "", 1),
		"duplicate":          good + strings.Split(good, "\n")[3] + "\n",
		"extra":              good + "daemon - - none < 1 amd64 none /stage/archives/daemon.deb\n",
		"old protocol":       strings.Replace(good, "VERSION 3", "VERSION 2", 1),
		"unknown protocol":   strings.Replace(good, "VERSION 3", "VERSION 4", 1),
		"oversize":           good + strings.Repeat("x", 256<<10),
		"truncated":          strings.Split(good, "\n\n")[0],
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if validatePlan(strings.NewReader(input), "/stage/archives") == nil {
				t.Fatal("accepted unreviewed action")
			}
		})
	}
}
func statusFixture(installed bool) []byte {
	data, _ := profileFS.ReadFile("profile/baseline.tsv")
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n")[1:] {
		p := strings.Split(line, "\t")
		fmt.Fprintf(&out, "Package: %s\nVersion: %s\nArchitecture: %s\nStatus: install ok installed\n\n", p[0], p[1], p[2])
	}
	if installed {
		for _, a := range archives() {
			fmt.Fprintf(&out, "Package: %s\nVersion: %s\nArchitecture: %s\nStatus: install ok installed\n\n", a.Name, a.Version, a.Arch)
		}
	}
	return []byte(out.String())
}
func TestBaselineAndPostconditions(t *testing.T) {
	before, after := statusFixture(false), statusFixture(true)
	if baseline(before, false) != nil || baseline(after, true) != nil || unchangedOtherPackages(before, after) != nil {
		t.Fatal("valid profile rejected")
	}
	for _, bad := range [][]byte{after, append(bytes.Clone(before), before...), bytes.Replace(before, []byte("install ok installed"), []byte("install ok triggers-pending"), 1), bytes.Replace(before, []byte("amd64"), []byte("arm64"), 1), bytes.Replace(before, []byte("Version: 3.152"), []byte("Version: 3.153"), 1)} {
		if baseline(bad, false) == nil {
			t.Fatal("baseline admitted")
		}
	}
	if unchangedOtherPackages(before, bytes.Replace(after, []byte("Version: 3.152"), []byte("Version: 3.153"), 1)) == nil {
		t.Fatal("unrelated upgrade accepted")
	}
}
