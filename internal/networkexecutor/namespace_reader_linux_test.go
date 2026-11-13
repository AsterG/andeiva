package networkexecutor

import (
	"context"
	"testing"
)

func TestOwnedReaderSupplementaryAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name            string
		groups          []int
		primary, reader uint32
		ok              bool
	}{
		{"legacy empty", nil, 1001, 0, true},
		{"legacy primary", []int{1001}, 1001, 0, true},
		{"legacy rejects reader", []int{1001, 1002}, 1001, 0, false},
		{"reader only", []int{1002}, 1001, 1002, true},
		{"reader with primary", []int{1001, 1002}, 1001, 1002, true},
		{"reader absent", []int{1001}, 1001, 1002, false},
		{"extra group", []int{1001, 1002, 1003}, 1001, 1002, false},
		{"negative", []int{-1, 1002}, 1001, 1002, false},
		{"root group", []int{0, 1002}, 1001, 1002, false},
		{"shared primary", []int{1001}, 1001, 1001, false},
		{"invalid reader", []int{1001}, 1001, ^uint32(0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (ownedSupplementaryGroups(tc.groups, tc.primary, tc.reader) == nil) != tc.ok {
				t.Fatal("wrong allowlist result")
			}
		})
	}
	for _, reader := range []uint32{0, 1001, ^uint32(0)} {
		if executor, e := NewInOwnedNamespaceWithReader(context.Background(), nil, nil, OwnedNamespaceIdentity{GID: 1001}, reader); e == nil || executor != nil {
			t.Fatal("invalid profile constructed executor")
		}
	}
}
