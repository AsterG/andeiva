// Copyright 2026 ASTERG. Licensed under the Apache License, Version 2.0.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//go:embed profile/*
var profileFS embed.FS

var errProfile = errors.New("ANDEIVA_DHCP_OFFLINE_PROFILE")
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type archive struct {
	Name, Version, Arch, Hash string
	Size                      int64
}

func (a archive) Leaf() string {
	return a.Name + "_" + strings.ReplaceAll(a.Version, ":", "%3a") + "_" + a.Arch + ".deb"
}
func archives() []archive {
	data, err := profileFS.ReadFile("profile/archives.tsv")
	if err != nil {
		panic(err)
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = '\t'
	rows, err := r.ReadAll()
	if err != nil {
		panic(err)
	}
	var result []archive
	for _, row := range rows[1:] {
		n, e := strconv.ParseInt(row[4], 10, 64)
		if e != nil {
			panic(e)
		}
		result = append(result, archive{row[0], row[1], row[2], row[3], n})
	}
	return result
}
func sha(data []byte) string { d := sha256.Sum256(data); return hex.EncodeToString(d[:]) }

// VERSION 3 contains the entire real APT action list, not simulation stdout.
// Only fresh unpack + configure for each reviewed archive is accepted.
func validatePlan(reader io.Reader, dir string) error {
	data, err := io.ReadAll(io.LimitReader(reader, (256<<10)+1))
	if err != nil || len(data) > 256<<10 {
		return errProfile
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	if !scanner.Scan() || scanner.Text() != "VERSION 3" {
		return errProfile
	}
	ended := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			ended = true
			break
		}
		if !strings.Contains(line, "=") {
			return errProfile
		}
	}
	if !ended {
		return errProfile
	}
	expected := map[string]archive{}
	for _, a := range archives() {
		expected[a.Name] = a
	}
	seen := map[string]int{}
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) != 9 {
			return errProfile
		}
		a, ok := expected[f[0]]
		if !ok || f[1] != "-" || f[2] != "-" || f[4] != "<" || f[5] != a.Version || f[6] != a.Arch {
			return errProfile
		}
		if (f[3] != "none" && f[3] != "no") || (f[7] != "none" && f[7] != "no" && f[7] != "same" && f[7] != "foreign" && f[7] != "allowed") {
			return errProfile
		}
		switch f[8] {
		case filepath.Join(dir, a.Leaf()):
			if seen[a.Name] != 0 {
				return errProfile
			}
			seen[a.Name] = 1
		case "**CONFIGURE**":
			if seen[a.Name] != 1 {
				return errProfile
			}
			seen[a.Name] = 2
		default:
			return errProfile
		}
	}
	if scanner.Err() != nil || len(seen) != len(expected) {
		return errProfile
	}
	for _, n := range seen {
		if n != 2 {
			return errProfile
		}
	}
	return nil
}

func parseControl(data []byte) ([]map[string]string, error) {
	if len(data) > 8<<20 {
		return nil, errProfile
	}
	var out []map[string]string
	current := map[string]string{}
	key := ""
	for _, line := range strings.Split(string(data)+"\n", "\n") {
		if line == "" {
			if len(current) > 0 {
				out = append(out, current)
			}
			current = map[string]string{}
			key = ""
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if key == "" {
				return nil, errProfile
			}
			current[key] += "\n" + line
			continue
		}
		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 || p[0] == "" {
			return nil, errProfile
		}
		if _, exists := current[p[0]]; exists {
			return nil, errProfile
		}
		key = p[0]
		current[key] = strings.TrimPrefix(p[1], " ")
	}
	return out, nil
}

func baseline(status []byte, installed bool) error {
	rows, err := parseControl(status)
	if err != nil {
		return err
	}
	all := map[string]map[string]string{}
	for _, r := range rows {
		n := r["Package"]
		if n == "" || all[n] != nil {
			return errProfile
		}
		all[n] = r
		if r["Status"] != "install ok installed" {
			return fmt.Errorf("%w: non-installed state %s", errProfile, n)
		} // refuse pending triggers/config-files/foreign partial states
	}
	data, _ := profileFS.ReadFile("profile/baseline.tsv")
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = '\t'
	expected, err := r.ReadAll()
	if err != nil {
		return err
	}
	for _, p := range expected[1:] {
		v := all[p[0]]
		if v == nil || v["Version"] != p[1] || v["Architecture"] != p[2] {
			return fmt.Errorf("%w: baseline %s", errProfile, p[0])
		}
	}
	for _, a := range archives() {
		p := all[a.Name]
		if !installed {
			if p != nil {
				return errProfile
			}
		} else if p == nil || p["Version"] != a.Version || p["Architecture"] != a.Arch {
			return errProfile
		}
	}
	return nil
}

func unchangedOtherPackages(before, after []byte) error {
	a, e := parseControl(before)
	if e != nil {
		return e
	}
	b, e := parseControl(after)
	if e != nil {
		return e
	}
	all := map[string]map[string]string{}
	for _, r := range b {
		all[r["Package"]] = r
	}
	if len(b) != len(a)+10 {
		return errProfile
	}
	for _, r := range a {
		n := r["Package"]
		s := all[n]
		if s == nil || s["Version"] != r["Version"] || s["Architecture"] != r["Architecture"] || s["Status"] != r["Status"] {
			return errProfile
		}
	}
	return nil
}
