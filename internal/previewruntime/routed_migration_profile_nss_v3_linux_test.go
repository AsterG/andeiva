//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRoutedMigrationProfileNSSV3(t *testing.T) {
	conf := []byte("passwd: files systemd\ngroup: files systemd\n")
	clean := []byte("root:x:0:0:root:/root:/bin/sh\nservice:x:100:100::/:/bin/false\n")
	calls := 0
	enumerate := func(context.Context) ([]byte, error) { calls++; return clean, nil }
	if e := checkProfileNSSV3(context.Background(), conf, 62004, enumerate); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"passwd: sss\ngroup: files\n", "passwd: files ldap\ngroup: files\n", "passwd: files [NOTFOUND=return]\ngroup: files\n", "passwd: files\ngroup: nis\n", "passwd: files\n", "passwd: files\npasswd: systemd\ngroup: files\n"} {
		calls = 0
		if checkProfileNSSV3(context.Background(), []byte(bad), 62004, enumerate) == nil || calls != 0 {
			t.Fatal("unsupported provider enumerated/accepted", bad)
		}
	}
	for _, bad := range [][]byte{[]byte("foreign:x:500:62004::/:/bin/sh\n"), []byte("root:x:0:0::/:/bin/sh"), []byte(strings.Repeat("x", profileNSSLimitV3+1)), []byte("bad:x:0:broken::/:/bin/sh\n")} {
		if checkProfileNSSV3(context.Background(), conf, 62004, func(context.Context) ([]byte, error) { return bad, nil }) == nil {
			t.Fatal("invalid/foreign passwd accepted")
		}
	}
	if checkProfileNSSV3(context.Background(), conf, 62004, func(context.Context) ([]byte, error) { return nil, errors.New("NSS failed") }) == nil {
		t.Fatal("NSS failure accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if checkProfileNSSV3(ctx, conf, 62004, enumerate) == nil || calls != 0 {
		t.Fatal("cancelled enumeration")
	}
	short, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	if checkProfileNSSV3(short, conf, 62004, func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return clean, nil }) == nil {
		t.Fatal("timed out enumeration accepted")
	}
	var bounded profileNSSOutputV3
	if _, e := bounded.Write(make([]byte, profileNSSLimitV3)); e != nil {
		t.Fatal(e)
	}
	if _, e := bounded.Write([]byte("x")); e == nil || bounded.Len() != profileNSSLimitV3 {
		t.Fatal("output limit not enforced")
	}
}
