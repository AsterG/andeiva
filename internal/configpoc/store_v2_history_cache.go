package configpoc

import (
	"bytes"
	"crypto/sha256"
	"os"
)

type historyReadEntryV2 struct {
	info   os.FileInfo
	data   []byte
	size   int
	digest [sha256.Size]byte
}

// Optional per-read payloads share the existing raw byte allowance. On
// pressure, retain identity and a content fingerprint for final readback.
// That index is bounded by the same unique-object cap as the graph.
type historyReadCacheV2 struct {
	entries map[string]historyReadEntryV2
	bytes   uint64
	drained bool
}

func (c *historyReadCacheV2) keep(r *v2ReachabilityReader, name string, info os.FileInfo, data []byte) bool {
	if name == "selected.json" || c.drained || uint64(len(c.entries)) >= r.budget.Objects {
		return false
	}
	used := c.bytes + r.cache.bytes
	if used > r.budget.ActiveBytes/2 || uint64(len(data)) > r.budget.ActiveBytes/2-used {
		return false
	}
	c.entries[name] = historyReadEntryV2{info: info, data: data, size: len(data), digest: sha256.Sum256(data)}
	c.bytes += uint64(len(data))
	return true
}

func (r *v2ReachabilityReader) selectedActiveFitsV2(n uint64) bool {
	fits := r.active <= r.budget.ActiveBytes && n <= r.budget.ActiveBytes-r.active
	if fits || r.history == nil || r.history.bytes == 0 {
		return fits
	}
	r.history.releasePayloads(r)
	return r.active <= r.budget.ActiveBytes && n <= r.budget.ActiveBytes-r.active
}

func (c *historyReadCacheV2) releasePayloads(r *v2ReachabilityReader) {
	for name, entry := range c.entries {
		entry.data = nil
		c.entries[name] = entry
	}
	r.active -= c.bytes
	c.bytes = 0
	c.drained = true
}

func (c *historyReadCacheV2) revalidate(r *v2ReachabilityReader) error {
	for name, entry := range c.entries {
		if err := r.revalidateUnpinnedV2(name, entry.info, entry.size, func(data []byte) bool {
			// The readback may have released optional payloads to make room.
			if previous := c.entries[name].data; previous != nil {
				return bytes.Equal(previous, data)
			}
			return sha256.Sum256(data) == entry.digest
		}); err != nil {
			return err
		}
	}
	return nil
}
