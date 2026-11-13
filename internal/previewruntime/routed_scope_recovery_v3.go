package previewruntime

import (
	"bytes"
	"encoding/json"
)

const RoutedScopeRecoveryRecordSizeV3 = 4096

// This operational record binds retained descriptors. It is neither selected
// configuration nor evidence that processes or the namespace were retired.
type RoutedScopeRecoveryRecordV3 struct {
	Version          int                       `json:"version"`
	Phase            string                    `json:"phase"`
	Metadata         Metadata                  `json:"metadata"`
	Identities       Identities                `json:"identities"`
	MetadataSHA256   string                    `json:"metadata_sha256"`
	Gateway          RoutedScopeRecoveryFileV3 `json:"gateway"`
	Mount            RoutedScopeRecoveryFileV3 `json:"mount"`
	Underlay         RoutedScopeRecoveryFileV3 `json:"underlay"`
	Directory        RoutedScopeRecoveryFileV3 `json:"directory"`
	Cgroup           RoutedScopeRecoveryFileV3 `json:"cgroup"`
	CgroupEvents     RoutedScopeRecoveryFileV3 `json:"cgroup_events"`
	CgroupInvocation string                    `json:"cgroup_invocation"`
	IntegritySHA256  string                    `json:"integrity_sha256,omitempty"`
}

type RoutedScopeRecoveryFileV3 struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (r RoutedScopeRecoveryRecordV3) valid() bool {
	if !validHex(r.CgroupInvocation, 16) || r.Version != 3 || r.Phase != "pinned" || r.Metadata.ValidateRouted() != nil || r.Identities.Validate() != nil || r.MetadataSHA256 != retirementDigestV3(marshal(r.Metadata)) || r.Gateway.Inode != r.Metadata.GatewayNamespace {
		return false
	}
	seen := map[RoutedScopeRecoveryFileV3]bool{}
	for _, id := range []RoutedScopeRecoveryFileV3{r.Gateway, r.Mount, r.Underlay, r.Directory, r.Cgroup, r.CgroupEvents} {
		if id.Device == 0 || id.Inode == 0 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// The checksum detects torn writes; only root ownership and inherited FD
// provenance authenticate the record. No value here authorizes cleanup.
func EncodeRoutedScopeRecoveryV3(r RoutedScopeRecoveryRecordV3) ([]byte, error) {
	if !r.valid() || r.IntegritySHA256 != "" {
		return nil, ErrIdentity
	}
	unsigned, err := json.Marshal(r)
	if err != nil {
		return nil, ErrIdentity
	}
	r.IntegritySHA256 = retirementDigestV3(unsigned)
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > RoutedScopeRecoveryRecordSizeV3 {
		return nil, ErrIdentity
	}
	return append(raw, bytes.Repeat([]byte{' '}, RoutedScopeRecoveryRecordSizeV3-len(raw))...), nil
}
func DecodeRoutedScopeRecoveryV3(raw []byte) (RoutedScopeRecoveryRecordV3, error) {
	var r RoutedScopeRecoveryRecordV3
	if len(raw) != RoutedScopeRecoveryRecordSizeV3 {
		return r, ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || !retirementHashV3(r.IntegritySHA256) {
		return RoutedScopeRecoveryRecordV3{}, ErrIdentity
	}
	unsigned := r
	unsigned.IntegritySHA256 = ""
	expected, err := EncodeRoutedScopeRecoveryV3(unsigned)
	if err != nil || !bytes.Equal(expected, raw) {
		return RoutedScopeRecoveryRecordV3{}, ErrIdentity
	}
	return r, nil
}
