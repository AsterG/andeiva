//go:build linux

package configpoc

import (
	"os"
	"testing"
	"time"
)

func v2ActualUsage(t *testing.T, area *os.Root) v2Budget {
	t.Helper()
	dir, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if err = dir.Close(); err != nil {
		t.Fatal(err)
	}
	var used v2Budget
	for _, entry := range entries {
		info, e := area.Lstat(entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		size := info.Size()
		if size < 0 {
			t.Fatal("negative size")
		}
		used.Bytes += uint64(size)
		used.Inodes++
	}
	return used
}

func TestV2OpenAccountsAfterExclusiveLock(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	before := v2ActualUsage(t, area)
	b, err := openV2BeforeLock(area, s.budget, func() error {
		if _, e := s.namespace(subject, "firewall", now, time.Hour); e != nil {
			return e
		}
		return s.close()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	actual := v2ActualUsage(t, area)
	if actual == before {
		t.Fatal("fixture did not publish between scan and lock")
	}
	if b.used != actual {
		t.Fatalf("stale pre-lock budget: used=%+v actual=%+v preflight=%+v", b.used, actual, before)
	}
	if len(b.state.Namespaces) != 1 {
		t.Fatal("did not load new selected state")
	}
}

func TestV2OpenRescansPartiallyWrittenUnselectedObject(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	data, hash, err := v2Canonical(map[string]string{"format": v2Format, "fixture": "interrupted before fsync"})
	if err != nil {
		t.Fatal(err)
	}
	name, _ := v2ObjectName(hash)
	file, err := area.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	middle := len(data) / 2
	if _, err = file.Write(data[:middle]); err != nil {
		t.Fatal(err)
	}
	before := v2ActualUsage(t, area)
	b, err := openV2BeforeLock(area, s.budget, func() error {
		if _, e := file.Write(data[middle:]); e != nil {
			return e
		}
		if e := file.Sync(); e != nil {
			return e
		}
		if e := file.Close(); e != nil {
			return e
		}
		return s.close()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	actual := v2ActualUsage(t, area)
	if actual.Bytes <= before.Bytes || b.used != actual {
		t.Fatalf("partial bytes remained authoritative: before=%+v used=%+v actual=%+v", before, b.used, actual)
	}
}

func TestV2PrepareRechecksEmptyAreaAfterLock(t *testing.T) {
	seed, _, now, subject := v2Fixture(t, 64)
	area, _ := checkpointFixtureArea(t)
	initial := clone(seed.state)
	b, err := prepareV2BeforeLock(area, seed.budget, initial, func() error {
		a, e := createV2(area, seed.budget, initial)
		if e != nil {
			return e
		}
		if _, e = a.namespace(subject, "firewall", now, time.Hour); e != nil {
			_ = a.close()
			return e
		}
		return a.close()
	})
	if err == nil {
		_ = b.close()
		t.Fatal("stale empty preflight accepted another initializer's store")
	}
	reopened, err := openV2(area, seed.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if len(reopened.state.Namespaces) != 1 {
		t.Fatal("existing selected state lost")
	}
}
