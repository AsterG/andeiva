package trafficprobe

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
)

const maxCABytes = 1024 * 1024

func readCA(path string) (pool *x509.CertPool, result error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalid
	}
	for part := path; ; part = filepath.Dir(part) {
		info, err := os.Lstat(part)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errInvalid
		}
		if part == filepath.Dir(part) {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&022 != 0 || before.Size() < 1 || before.Size() > maxCABytes {
		return nil, errInvalid
	}
	file, err := openCAFile(path)
	if err != nil {
		return nil, errInvalid
	}
	defer func() {
		if file.Close() != nil {
			pool, result = nil, errInvalid
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameCAFile(before, opened) {
		return nil, errInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCABytes+1))
	if err != nil || int64(len(data)) != opened.Size() || len(data) > maxCABytes {
		return nil, errInvalid
	}
	after, err := file.Stat()
	if err != nil || !sameCAFile(opened, after) {
		return nil, errInvalid
	}
	current, err := os.Lstat(path)
	if err != nil || !sameCAFile(after, current) {
		return nil, errInvalid
	}
	pool = x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errInvalid
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || count >= 256 {
			return nil, errInvalid
		}
		pool.AddCert(certificate)
		count++
		data = rest
	}
	if count == 0 {
		return nil, errInvalid
	}
	return pool, nil
}

func sameCAFile(a, b os.FileInfo) bool {
	return b != nil && b.Mode().IsRegular() && b.Mode().Perm()&022 == 0 && b.Mode()&os.ModeSymlink == 0 && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
