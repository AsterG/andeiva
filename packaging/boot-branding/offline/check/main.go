// Command check validates experimental offline bundle data; it never installs it.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	versionRE = regexp.MustCompile(`^0\.1\.0~alpha[1-9][0-9]{0,5}$`)
	packageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,95}$`)
	debVerRE  = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~_-]{0,127}$`)
	fileRE    = regexp.MustCompile(`^archives/[0-9]{4}\.deb$`)
	suites    = []string{"trixie", "trixie-updates", "trixie-security"}
)

type item struct{ File, Origin, Name, Version, Arch, Hash string }
type manifest struct {
	Version string
	Items   []item
}

func reject() error { return errors.New("ANDEIVA_OFFLINE_INVALID_BUNDLE") }

const logLimit = 4 << 20
const truncatedLog = "\nANDEIVA_OFFLINE_LOG_TRUNCATED\n"

// Keep a footer-sized tail until EOF; overflow replaces it without exceeding limit.
// Continue draining after write failures so logging does not interrupt APT itself.
func boundedLog(dst io.Writer, src io.Reader, limit int) error {
	if limit < len(truncatedLog) {
		return reject()
	}
	remaining := limit - len(truncatedLog)
	tail := make([]byte, len(truncatedLog))
	tailSize, truncated := 0, false
	buffer := make([]byte, 64<<10)
	var firstErr error
	write := func(data []byte) {
		if firstErr != nil || len(data) == 0 {
			return
		}
		n, err := dst.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			firstErr = err
		}
	}
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			keep := min(remaining, len(chunk))
			write(chunk[:keep])
			remaining -= keep
			chunk = chunk[keep:]
			saved := copy(tail[tailSize:], chunk)
			tailSize += saved
			if saved < len(chunk) {
				truncated = true
			}
		}
		if readErr != nil {
			if readErr != io.EOF && firstErr == nil {
				firstErr = readErr
			}
			break
		}
	}
	if truncated {
		write([]byte(truncatedLog))
	} else {
		write(tail[:tailSize])
	}
	if firstErr != nil {
		return firstErr
	}
	if truncated {
		return errors.New("ANDEIVA_OFFLINE_LOG_TRUNCATED")
	}
	return nil
}

func capabilities(reader io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil || len(data) > 4096 {
		return reject()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	open, err := d.Token()
	if err != nil || open != json.Delim('{') || !d.More() {
		return reject()
	}
	key, err := d.Token()
	if err != nil || key != "offline_install_guard" {
		return reject()
	}
	value, err := d.Token()
	if err != nil || value != json.Number("1") || d.More() {
		return reject()
	}
	closeToken, err := d.Token()
	if err != nil || closeToken != json.Delim('}') {
		return reject()
	}
	if _, err = d.Token(); err != io.EOF {
		return reject()
	}
	return nil
}

func read(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, reject()
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, reject()
	}
	return data, err
}

func load(root *os.Root) (manifest, []byte, error) {
	var result manifest
	data, err := read(root, "manifest.tsv", 64<<10)
	if err != nil {
		return result, nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) < 3 || len(lines) > 129 {
		return result, nil, reject()
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != 3 || header[0] != "ANDEIVA_BOOT_OFFLINE_V1" || !versionRE.MatchString(header[1]) {
		return result, nil, reject()
	}
	epoch, err := strconv.ParseUint(header[2], 10, 32)
	if err != nil || strconv.FormatUint(epoch, 10) != header[2] {
		return result, nil, reject()
	}
	result.Version = header[1]
	names, files := map[string]bool{}, map[string]bool{}
	products := 0
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			return result, nil, reject()
		}
		i := item{fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]}
		if i.File != fmt.Sprintf("archives/%04d.deb", len(result.Items)+1) {
			return result, nil, reject()
		}
		digest, err := hex.DecodeString(i.Hash)
		if !fileRE.MatchString(i.File) || !packageRE.MatchString(i.Name) || !debVerRE.MatchString(i.Version) || (i.Arch != "all" && i.Arch != "amd64") || err != nil || len(digest) != 32 || strings.ToLower(i.Hash) != i.Hash || names[i.Name] || files[i.File] {
			return result, nil, reject()
		}
		product := i.Name == "andeiva-boot-branding" || i.Name == "andeiva-boot-activation"
		if product {
			if i.Origin != "product" || i.Version != result.Version {
				return result, nil, reject()
			}
			products++
		} else if i.Origin != "debian" || !qualifiedDependency(i) {
			return result, nil, reject()
		}
		names[i.Name], files[i.File] = true, true
		result.Items = append(result.Items, i)
	}
	if products != 2 {
		return result, nil, reject()
	}
	return result, data, nil
}

func hashFile(root *os.Root, name string, limit int64) (string, int64, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return "", 0, reject()
	}
	f, err := root.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit || n != info.Size() {
		return "", 0, reject()
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type bounded struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (w *bounded) Write(data []byte) (int, error) {
	n := len(data)
	left := w.limit - w.Len()
	if len(data) > left {
		w.overflow = true
		data = data[:left]
	}
	_, _ = w.Buffer.Write(data)
	return n, nil
}

func runFile(root *os.Root, name string, signature bool) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	limit := 4 << 20
	var authenticated *os.Root
	if signature {
		// sqv requires a new output file, and emits certificate IDs on stdout.
		dir, err := os.MkdirTemp("/tmp", "andeiva-offline-auth-")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		authenticated, err = os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		defer func() { _ = authenticated.Close() }()
		// Output is a fixed leaf in our new private directory, never a bundle path.
		cmd = exec.CommandContext(ctx, "/usr/bin/sqv", "--keyring", "/usr/share/keyrings/debian-archive-keyring.pgp", "--output", filepath.Join(dir, "verified"), "--cleartext", "/proc/self/fd/3") // #nosec G204 -- fixed executable/flags; only generated private output path varies.
		limit = 1 << 20
	} else {
		cmd = exec.CommandContext(ctx, "/usr/bin/dpkg-deb", "--ctrl-tarfile", "/proc/self/fd/3")
	}
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	out := &bounded{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || out.overflow {
		return nil, reject()
	}
	if signature {
		return read(authenticated, "verified", 1<<20)
	}
	return out.Bytes(), nil
}

func productControl(data []byte, want item) error {
	reader := tar.NewReader(bytes.NewReader(data))
	seen := map[string]bool{}
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count > 10 {
			return reject()
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size > 1<<20 || (name != "control" && name != "md5sums") || seen[name] {
			return reject()
		}
		seen[name] = true
		if name == "control" {
			body, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
			if err != nil || len(body) > 64<<10 || productFields(body, want) != nil {
				return reject()
			}
		}
	}
	if !seen["control"] || !seen["md5sums"] {
		return reject()
	}
	return nil
}

func productFields(body []byte, want item) error {
	expected := map[string]string{"Package": want.Name, "Version": want.Version, "Architecture": want.Arch, "Maintainer": "ASTERG", "Section": "admin", "Priority": "optional"}
	if want.Name == "andeiva-boot-activation" {
		if want.Arch != "amd64" {
			return reject()
		}
		expected["Homepage"] = "https://github.com/AsterG/andeiva"
		expected["X-Andeiva-Offline-Install-Guard"] = "1"
		expected["Depends"] = "andeiva-boot-branding (= " + want.Version + "), plymouth (= 24.004.60-5), plymouth-themes (= 24.004.60-5), initramfs-tools (= 0.148.4), grub-pc"
	} else if want.Name != "andeiva-boot-branding" || want.Arch != "all" {
		return reject()
	}
	seen := map[string]bool{}
	previous := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		if strings.HasPrefix(line, " ") && previous == "Description" {
			continue
		}
		pair := strings.SplitN(line, ": ", 2)
		if len(pair) != 2 || seen[pair[0]] || pair[1] == "" {
			return reject()
		}
		if pair[0] != "Description" && (expected[pair[0]] == "" || expected[pair[0]] != pair[1]) {
			return reject()
		}
		seen[pair[0]], previous = true, pair[0]
	}
	if len(seen) != len(expected)+1 || !seen["Description"] {
		return reject()
	}
	return nil
}

func releaseProof(data []byte, now time.Time, suite string) (string, int64, error) {
	var hash string
	var size int64
	sha := false
	dateSeen, untilSeen, codenameSeen := false, false, false
	var releaseDate, validUntil time.Time
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Codename:") {
			if codenameSeen || line != "Codename: "+suite {
				return "", 0, reject()
			}
			codenameSeen = true
		}
		if strings.HasPrefix(line, "Date:") || strings.HasPrefix(line, "Valid-Until:") {
			if strings.HasPrefix(line, "Date:") {
				if dateSeen {
					return "", 0, reject()
				}
				dateSeen = true
			} else {
				if untilSeen {
					return "", 0, reject()
				}
				untilSeen = true
			}
			value := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			date, err := time.Parse(time.RFC1123, value)
			if err != nil {
				return "", 0, reject()
			}
			if strings.HasPrefix(line, "Date:") {
				releaseDate = date
			} else {
				validUntil = date
			}
			if strings.HasPrefix(line, "Date:") && date.After(now.Add(24*time.Hour)) || strings.HasPrefix(line, "Valid-Until:") && !now.Before(date) {
				return "", 0, reject()
			}
		}
		if line == "SHA256:" {
			sha = true
			continue
		}
		if sha && !strings.HasPrefix(line, " ") {
			sha = false
		}
		if sha {
			f := strings.Fields(line)
			if len(f) == 3 && f[2] == "main/binary-amd64/Packages" {
				if hash != "" {
					return "", 0, reject()
				}
				hash = f[0]
				var err error
				size, err = strconv.ParseInt(f[1], 10, 64)
				if err != nil || size < 0 || size > 96<<20 {
					return "", 0, reject()
				}
			}
		}
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil || len(decoded) != 32 || size < 0 || !dateSeen || !codenameSeen || (suite != "trixie" && !untilSeen) || (untilSeen && releaseDate.After(validUntil)) {
		return "", 0, reject()
	}
	return hash, size, nil
}

func packageProof(root *os.Root, name string, needed map[string]item, found map[string]bool) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(io.LimitReader(f, (96<<20)+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	fields := map[string]string{}
	check := func() error {
		key := fields["Package"]
		if i, ok := needed[key]; ok && fields["Version"] == i.Version && fields["Architecture"] == i.Arch && fields["SHA256"] == i.Hash {
			found[key] = true
		}
		fields = map[string]string{}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := check(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, " ") {
			continue
		}
		pair := strings.SplitN(line, ": ", 2)
		if len(pair) == 2 {
			switch pair[0] {
			case "Package", "Version", "Architecture", "SHA256":
				if _, ok := fields[pair[0]]; ok {
					return reject()
				}
				fields[pair[0]] = pair[1]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return check()
}

// Enumerate only the fixed bundle directories, with an entry cap before allocation.
func tree(root *os.Root, expected map[string]bool) error {
	directories := map[string]bool{"archives": true, "provenance": true, "bin": true, "docs": true, "licenses": true}
	for _, directory := range []string{".", "archives", "provenance", "bin", "docs", "licenses"} {
		f, err := root.Open(directory)
		if err != nil {
			return reject()
		}
		entries, err := f.ReadDir(len(expected) + len(directories) + 1)
		_ = f.Close()
		if err != nil && err != io.EOF || len(entries) > len(expected)+len(directories) {
			return reject()
		}
		for _, entry := range entries {
			name := entry.Name()
			if directory != "." {
				name = directory + "/" + name
			}
			if directory == "." && directories[name] && entry.IsDir() {
				continue
			}
			if !expected[name] || !entry.Type().IsRegular() {
				return reject()
			}
		}
	}
	return nil
}

func verify(root *os.Root, authenticate func(string) ([]byte, error), now time.Time) (string, error) {
	m, _, err := load(root)
	if err != nil {
		return "", err
	}
	expected := map[string]bool{"manifest.tsv": true, "install.sh": true, "install-in-namespace.sh": true, "capture.sh": true, "bin/check": true, "README.md": true, "DESIGN.md": true, "docs/en.md": true, "docs/es.md": true, "docs/pt.md": true, "LICENSE": true, "NOTICE": true, "licenses/GO-LICENSE": true}
	for _, i := range m.Items {
		expected[i.File] = true
	}
	for _, suite := range suites {
		expected["provenance/"+suite+".InRelease"] = true
		expected["provenance/"+suite+".Packages"] = true
	}
	expected["SHA256SUMS"] = true
	if err := tree(root, expected); err != nil {
		return "", err
	}
	delete(expected, "SHA256SUMS")
	needed, found := map[string]item{}, map[string]bool{}
	var archiveBytes int64
	for _, i := range m.Items {
		expected[i.File] = true
		hash, n, err := hashFile(root, i.File, 64<<20)
		if err != nil || hash != i.Hash {
			return "", reject()
		}
		archiveBytes += n
		if archiveBytes > 128<<20 {
			return "", reject()
		}
		if i.Origin == "debian" {
			needed[i.Name] = i
		} else {
			control, err := runFile(root, i.File, false)
			if err != nil || productControl(control, i) != nil {
				return "", reject()
			}
		}
	}
	for _, suite := range suites {
		signed := "provenance/" + suite + ".InRelease"
		index := "provenance/" + suite + ".Packages"
		expected[signed], expected[index] = true, true
		if _, err := read(root, signed, 1<<20); err != nil {
			return "", err
		}
		release, err := authenticate(signed)
		if err != nil {
			return "", err
		}
		want, size, err := releaseProof(release, now, suite)
		if err != nil {
			return "", err
		}
		got, n, err := hashFile(root, index, 96<<20)
		if err != nil || n != size || got != want {
			return "", reject()
		}
		if err := packageProof(root, index, needed, found); err != nil {
			return "", err
		}
	}
	if len(found) != len(needed) {
		return "", reject()
	}
	sums, err := read(root, "SHA256SUMS", 64<<10)
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	previousName := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || !expected[parts[1]] || seen[parts[1]] || parts[1] <= previousName {
			return "", reject()
		}
		previousName = parts[1]
		got, _, err := hashFile(root, parts[1], 128<<20)
		if err != nil || got != parts[0] {
			return "", reject()
		}
		seen[parts[1]] = true
	}
	if len(seen) != len(expected) {
		return "", reject()
	}
	id := sha256.Sum256(sums)
	return hex.EncodeToString(id[:]), nil
}

func plan(m manifest, reader io.Reader) error {
	known := map[string]item{}
	for _, i := range m.Items {
		known[i.Name] = i
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, (64<<10)+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	total := 0
	for scanner.Scan() {
		total += len(scanner.Bytes()) + 1
		if total > 64<<10 {
			return reject()
		}
		f := strings.Fields(scanner.Text())
		if len(f) == 0 {
			continue
		}
		if f[0] == "Remv" || f[0] == "Purg" || f[0] == "E:" {
			return reject()
		}
		if f[0] != "Inst" && f[0] != "Conf" {
			continue
		}
		if len(f) < 3 || strings.HasPrefix(f[2], "[") {
			return reject()
		}
		name := strings.TrimSuffix(f[1], ":amd64")
		i, ok := known[name]
		if !ok || strings.TrimPrefix(f[2], "(") != i.Version {
			return reject()
		}
	}
	return scanner.Err()
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "ANDEIVA_OFFLINE_ARGUMENT")
		os.Exit(1)
	}
	root, err := os.OpenRoot(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ANDEIVA_OFFLINE_ROOT")
		os.Exit(1)
	}
	defer func() { _ = root.Close() }()
	switch os.Args[1] {
	case "baseline":
		err = baseline(root)
	case "cache-plan":
		var m manifest
		m, _, err = load(root)
		if err == nil {
			fmt.Print(cachePlan(m))
		}
	case "bounded-log":
		err = boundedLog(os.Stdout, os.Stdin, logLimit)
	case "capabilities":
		err = capabilities(os.Stdin)
	case "verify":
		var id string
		id, err = verify(root, func(name string) ([]byte, error) { return runFile(root, name, true) }, time.Now().UTC())
		if err == nil {
			fmt.Println(id)
		}
	case "plan":
		var m manifest
		m, _, err = load(root)
		if err == nil {
			err = plan(m, os.Stdin)
		}
	default:
		err = reject()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ANDEIVA_OFFLINE_VALIDATION_FAILED")
		os.Exit(1)
	}
}
