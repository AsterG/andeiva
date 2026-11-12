//go:build linux

package recoveryreserve

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func areaFor(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func prepared(t *testing.T, n int) (*Pool, *os.Root, string) {
	t.Helper()
	r, dir := areaFor(t)
	p, err := Prepare(r, n, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, r, dir
}

func TestPoolLifecycle(t *testing.T) {
	p, r, _ := prepared(t, 2)
	l, err := p.Claim("operation:1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Claim("operation:1")
	if err != nil || again != l {
		t.Fatalf("claim replay %v", err)
	}
	data := bytes.Repeat([]byte("x"), 4096)
	updated, err := p.Write(l, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Write(l, []byte("stale")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if _, err = p.Write(updated, make([]byte, 4097)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err = p.Claim("operation:2"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Claim("operation:3"); !errors.Is(err, ErrFull) {
		t.Fatalf("capacity: %v", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, err := p.Read("operation:1")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("retained payload: %v", err)
	}
	got[0] = 'z'
	fresh, err := p.Read("operation:1")
	if err != nil || fresh[0] != 'x' {
		t.Fatal("Read aliases storage")
	}
	if _, err = p.Claim("operation:3"); !errors.Is(err, ErrFull) {
		t.Fatal("reopen recycled a claim")
	}
}

func TestPoolZeroValueFailsClosed(t *testing.T) {
	for _, p := range []*Pool{nil, {}} {
		if _, err := p.Claim("owner"); err == nil {
			t.Fatal("zero Claim")
		}
		if _, err := p.Write(Lease{}, nil); err == nil {
			t.Fatal("zero Write")
		}
		if _, err := p.Read("owner"); err == nil {
			t.Fatal("zero Read")
		}
		if _, err := p.Binding(Lease{}); err == nil {
			t.Fatal("zero Binding")
		}
		if _, err := p.ReadBound(Binding{Owner: "owner", Sequence: 1}); err == nil {
			t.Fatal("zero ReadBound")
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPoolConcurrentClaims(t *testing.T) {
	p, _, _ := prepared(t, 2)
	var wg sync.WaitGroup
	leases := make(chan Lease, 20)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l, e := p.Claim("same-owner"); leases <- l; errs <- e }()
	}
	wg.Wait()
	close(leases)
	close(errs)
	var first Lease
	for l := range leases {
		if first.pool == nil {
			first = l
		}
		if l != first {
			t.Fatal("duplicate owner claimed multiple slots")
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Claim("second"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Claim("third"); !errors.Is(err, ErrFull) {
		t.Fatalf("full: %v", err)
	}
}

func TestPoolLockAndBoundaries(t *testing.T) {
	p, r, dir := prepared(t, 1)
	if _, err := Open(r); err == nil {
		t.Fatal("second writer opened")
	}
	for _, owner := range []string{"", "../x", "owner/other", "secret\nvalue", string(bytes.Repeat([]byte("x"), 129))} {
		if _, err := p.Claim(owner); !errors.Is(err, ErrInvalid) {
			t.Fatalf("owner accepted %q", owner)
		}
	}
	if _, err := p.Write(Lease{}, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("zero witness")
	}
	if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(r); err == nil {
		t.Fatal("foreign layout accepted")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "foreign")); err != nil || string(b) != "retain" {
		t.Fatal("foreign file removed")
	}
}

func TestPoolInvalidProfilesPreserveArea(t *testing.T) {
	for _, profile := range [][2]int{{0, 4096}, {33, 4096}, {1, 4095}, {1, 1 << 21}} {
		r, dir := areaFor(t)
		if _, err := Prepare(r, profile[0], profile[1]); !errors.Is(err, ErrInvalid) {
			t.Fatal(profile, err)
		}
		es, err := os.ReadDir(dir)
		if err != nil || len(es) != 0 {
			t.Fatal("invalid prepare changed area")
		}
	}
	r, dir := areaFor(t)
	if err := os.WriteFile(filepath.Join(dir, "foreign"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(r, 1, 4096); err == nil {
		t.Fatal("prepare foreign area")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "foreign")); err != nil || string(b) != "preserve" {
		t.Fatal("foreign changed")
	}
}

func TestPoolPermissionAndReplacement(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "hardlink", "replace", "truncate"} {
		t.Run(kind, func(t *testing.T) {
			p, r, dir := prepared(t, 1)
			l, err := p.Claim("op")
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, slotName(0))
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "mode":
				err = os.Chmod(name, 0644)
			case "symlink":
				err = os.Rename(name, name+".old")
				if err == nil {
					err = os.Symlink(name+".old", name)
				}
			case "hardlink":
				err = os.Link(name, name+".alias")
			case "replace":
				err = os.Rename(name, name+".old")
				if err == nil {
					err = os.WriteFile(name, original, 0600)
				}
			case "truncate":
				err = os.Truncate(name, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Write(l, []byte("must fail")); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unsafe write: %v", err)
			}
			_ = p.Close()
			if _, err = Open(r); err == nil {
				t.Fatal("unsafe reopen")
			}
		})
	}
}

func TestPoolInterruptedPublication(t *testing.T) {
	for _, point := range []string{"payload_synced", "header_written", "header_synced"} {
		t.Run(point, func(t *testing.T) {
			p, r, _ := prepared(t, 1)
			l, err := p.Claim("op")
			if err != nil {
				t.Fatal(err)
			}
			l, err = p.Write(l, []byte("previous"))
			if err != nil {
				t.Fatal(err)
			}
			p.hook = func(at string) error {
				if at == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err = p.Write(l, []byte("target")); !errors.Is(err, ErrUnavailable) {
				t.Fatal("fault ignored")
			}
			if _, err = p.Claim("another"); !errors.Is(err, ErrUnavailable) {
				t.Fatal("uncertain handle not fenced")
			}
			_ = p.Close()
			p, err = Open(r)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			got, err := p.Read("op")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "previous" && string(got) != "target" {
				t.Fatalf("partial result %q", got)
			}
			if point == "payload_synced" && string(got) != "previous" {
				t.Fatal("unpublished payload selected")
			}
			if point == "header_synced" && string(got) != "target" {
				t.Fatal("durably selected target lost")
			}
		})
	}
}

func TestPoolCorruptBanks(t *testing.T) {
	p, r, dir := prepared(t, 1)
	l, err := p.Claim("op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Write(l, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	f, err := os.OpenFile(filepath.Join(dir, slotName(0)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	for bank := 0; bank < 2; bank++ {
		if _, err = f.WriteAt([]byte("corrupt"), int64(bank)*bankSize(4096)); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	if _, err = Open(r); err == nil {
		t.Fatal("corrupt banks accepted")
	}
}

func TestPoolBoundReadRejectsFallback(t *testing.T) {
	p, r, dir := prepared(t, 1)
	l, err := p.Claim("op")
	if err != nil {
		t.Fatal(err)
	}
	l, err = p.Write(l, []byte("selected"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := p.Binding(l)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.ReadBound(binding); err != nil || string(got) != "selected" {
		t.Fatal(err)
	}
	_ = p.Close()
	f, err := os.OpenFile(filepath.Join(dir, slotName(0)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("corrupt"), int64(binding.Sequence%2)*bankSize(4096)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	p, err = Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = p.ReadBound(binding); !errors.Is(err, ErrUnavailable) {
		t.Fatal("older bank accepted as selected record")
	}
}

func TestPoolCorruptClaimCannotBecomeFree(t *testing.T) {
	p, r, dir := prepared(t, 1)
	l, err := p.Claim("reserved")
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	f, err := os.OpenFile(filepath.Join(dir, slotName(0)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt([]byte("corrupt"), int64(l.sequence%2)*bankSize(4096)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = Open(r); err == nil {
		t.Fatal("damaged reservation was released")
	}
}

func TestPoolProcessInterruption(t *testing.T) {
	if os.Getenv("ANDEIVA_RESERVE_CHILD") == "1" {
		r, err := os.OpenRoot(os.Getenv("ANDEIVA_RESERVE_AREA"))
		if err != nil {
			os.Exit(70)
		}
		p, err := Open(r)
		if err != nil {
			os.Exit(71)
		}
		l, err := p.Claim("op")
		if err != nil {
			os.Exit(72)
		}
		p.hook = func(at string) error {
			if at == os.Getenv("ANDEIVA_RESERVE_POINT") {
				os.Exit(73)
			}
			return nil
		}
		_, _ = p.Write(l, []byte("target"))
		os.Exit(74)
	}
	for _, point := range []string{"payload_synced", "header_written", "header_synced"} {
		t.Run(point, func(t *testing.T) {
			p, r, dir := prepared(t, 1)
			l, err := p.Claim("op")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Write(l, []byte("previous")); err != nil {
				t.Fatal(err)
			}
			_ = p.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestPoolProcessInterruption$")
			cmd.Env = append(os.Environ(), "ANDEIVA_RESERVE_CHILD=1", "ANDEIVA_RESERVE_AREA="+dir, "ANDEIVA_RESERVE_POINT="+point)
			err = cmd.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("child did not reach boundary: %v", err)
			}
			p, err = Open(r)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			data, err := p.Read("op")
			if err != nil || (string(data) != "previous" && string(data) != "target") {
				t.Fatalf("recovery %q %v", data, err)
			}
		})
	}
}
