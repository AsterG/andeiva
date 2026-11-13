//go:build linux

package configpoc

import (
	"context"
	"fmt"
	"testing"
)

func TestSelectedCacheV2BoundedFallback(t *testing.T) {
	for _, memory := range []bool{false, true} {
		t.Run(fmt.Sprint(memory), func(t *testing.T) {
			r, c, _ := selectedCacheFixtureV2(t)
			if memory {
				r.budget.ActiveBytes = 256
			}
			for i := 0; i < 2*selectedCacheFilesV2+2; i++ {
				if i == selectedCacheFilesV2 {
					if !memory && len(r.cache.entries) != r.cache.files/2 {
						t.Fatal("general reads consumed work capacity")
					}
					r.cache.workRead = true
				}
				value := struct {
					Index int `json:"index"`
				}{i}
				hash, err := c.store.object(value)
				if err != nil {
					t.Fatal(err)
				}
				var got struct {
					Index int `json:"index"`
				}
				if err = r.object(hash, &got); err != nil || got != value {
					t.Fatal("bounded fallback lost validation", err)
				}
				if len(r.cache.entries) > selectedCacheFilesV2 || r.cache.bytes > r.budget.ActiveBytes/2 || r.active != r.cache.bytes {
					t.Fatal("cache exceeded cap")
				}
			}
			if !memory && len(r.cache.entries) != r.cache.files {
				t.Fatal("FD cap not exercised")
			}
			t.Logf("retained descriptors=%d payload=%d peak active=%d physical bytes read=%d", len(r.cache.entries), r.cache.bytes, r.report.PeakActiveBytes, r.report.BytesRead)
			if err := r.cache.revalidate(r); err != nil {
				t.Fatal(err)
			}
			if err := r.cache.close(r); err != nil || r.active != 0 {
				t.Fatal("release", err)
			}
		})
	}
}
func TestSelectedCacheV2UnlinkAndNextCall(t *testing.T) {
	r, _, name := selectedCacheFixtureV2(t)
	if _, release, err := r.read(name, v2ObjectLimit); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if err := r.area.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := r.cache.revalidate(r); err == nil {
		t.Fatal("unlinked cached inode accepted")
	}
}
func TestSelectedReaderV2DoesNotReusePriorCall(t *testing.T) {
	reader, c, _ := selectedReaderFixtureV2(t)
	if _, err := reader.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := reader.area.Remove("object-" + c.store.selection.State + ".json"); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Observe(context.Background()); err == nil {
		t.Fatal("previous call concealed missing selected state")
	}
}
func TestSelectedCacheV2RetainedResourceSample(t *testing.T) {
	reader, _, _ := selectedIntentFixtureV2(t)
	v, err := reader.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := v.graph.cache
	t.Logf("selected intent fixture: FDs=%d raw=%d work payload=%d plans=%d hits=%d peak active=%d", len(c.entries), c.bytes, c.planBytes, len(c.plans), c.hits, v.graph.report.PeakActiveBytes)
	if err = c.close(v.graph); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedCacheV2DescriptorLimit(t *testing.T) {
	for _, tc := range []struct {
		limit uint64
		want  int
	}{{0, 0}, {3, 1}, {4, 2}, {256, 128}, {1024, 256}, {^uint64(0), 256}} {
		if got := selectedCacheFilesForLimitV2(tc.limit); got != tc.want {
			t.Fatalf("limit %d: %d", tc.limit, got)
		}
	}
}

func TestSelectedCacheV2DescriptorHeadroom(t *testing.T) {
	for _, tc := range []struct {
		limit, used uint64
		want        int
	}{{256, 70, 128}, {256, 150, 74}, {256, 224, 0}, {256, 256, 0}, {256, ^uint64(0), 0}, {^uint64(0), 0, 256}} {
		if got := selectedCacheFilesForUsageV2(tc.limit, tc.used); got != tc.want {
			t.Fatalf("limit %d used %d: %d", tc.limit, tc.used, got)
		}
	}
}
