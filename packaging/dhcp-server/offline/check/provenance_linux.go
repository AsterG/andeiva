package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type provenanceFile struct {
	Source, Filename, SHA256 string
	Bytes                    int64
}

func releaseTime(body []byte, now time.Time) error {
	rows, e := parseControl(body)
	if e != nil || len(rows) != 1 {
		return errProfile
	}
	r := rows[0]
	parse := func(s string) (time.Time, error) {
		t, e := time.Parse(time.RFC1123Z, s)
		if e != nil {
			return time.Parse(time.RFC1123, s)
		}
		return t, e
	}
	date, e := parse(r["Date"])
	if e != nil || date.After(now.Add(5*time.Minute)) {
		return errProfile
	}
	switch r["Codename"] {
	case "trixie":
	case "trixie-updates", "trixie-security":
		until, e := parse(r["Valid-Until"])
		if e != nil || until.Before(date) || now.After(until) {
			return errProfile
		}
	default:
		return errProfile
	}
	return nil
}
func authenticateRelease(path string) ([]byte, error) {
	for _, p := range []string{"/usr/bin/sqv", "/usr/share/keyrings/debian-archive-keyring.pgp"} {
		if e := secure(p, false); e != nil {
			return nil, e
		}
	}
	// The bundle parent is root-only trusted storage; no global trust modifications.
	dir, e := os.MkdirTemp(bundleBase, ".verify-")
	if e != nil {
		return nil, e
	}
	defer os.Remove(dir)
	output := filepath.Join(dir, "verified")
	defer os.Remove(output)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sqv", "--keyring", "/usr/share/keyrings/debian-archive-keyring.pgp", "--output", output, "--cleartext", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	out := &boundedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	if e := cmd.Run(); e != nil || out.overflow {
		return nil, errProfile
	}
	return readFile(output, 1<<20)
}
func verifyProvenance(bundle string) error {
	raw, e := profileFS.ReadFile("profile/provenance.json")
	if e != nil {
		return e
	}
	var files []provenanceFile
	if e := json.Unmarshal(raw, &files); e != nil {
		return e
	}
	releases := map[string][]byte{}
	for _, p := range files {
		path := filepath.Join(bundle, "provenance", p.Source, p.Filename)
		hash, n, e := fileHash(path, p.Bytes)
		if e != nil || hash != p.SHA256 || n != p.Bytes {
			return errProfile
		}
		if strings.HasSuffix(p.Filename, "_InRelease") {
			body, e := authenticateRelease(path)
			if e != nil {
				return e
			}
			if e := releaseTime(body, time.Now()); e != nil {
				return e
			}
			releases[p.Source+"/"+strings.TrimSuffix(p.Filename, "_InRelease")] = body
		}
	}
	for _, p := range files {
		if strings.HasSuffix(p.Filename, "_InRelease") {
			continue
		}
		suffix, key := "_main_source_Sources", "main/source/Sources"
		if p.Source == "binary" {
			suffix, key = "_main_binary-amd64_Packages", "main/binary-amd64/Packages"
		}
		body := releases[p.Source+"/"+strings.TrimSuffix(p.Filename, suffix)]
		rows, e := parseControl(body)
		if e != nil || len(rows) != 1 {
			return errProfile
		}
		found := 0
		for _, line := range strings.Split(rows[0]["SHA256"], "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[2] == key {
				found++
				if f[0] != p.SHA256 || f[1] != strconv.FormatInt(p.Bytes, 10) {
					return errProfile
				}
			}
		}
		if found != 1 {
			return errProfile
		}
	}
	return nil
}
