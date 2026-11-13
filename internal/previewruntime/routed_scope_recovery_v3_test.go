package previewruntime

import (
	"bytes"
	"strings"
	"testing"
)

func scopeRecoveryRecordFixtureV3() RoutedScopeRecoveryRecordV3 {
	m := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 40, GatewayNamespace: 42}
	return RoutedScopeRecoveryRecordV3{Version: 3, Phase: "pinned", Metadata: m, Identities: Identities{SchemaVersion: 1, APIUID: 62001, APIGID: 62001, HelperUID: 62002, IPCGID: 62003}, MetadataSHA256: retirementDigestV3(marshal(m)), Gateway: RoutedScopeRecoveryFileV3{4, 42}, Mount: RoutedScopeRecoveryFileV3{4, 45}, Underlay: RoutedScopeRecoveryFileV3{1, 55}, Directory: RoutedScopeRecoveryFileV3{1, 56}, Cgroup: RoutedScopeRecoveryFileV3{2, 57}, CgroupEvents: RoutedScopeRecoveryFileV3{2, 58}}
}
func TestRoutedScopeRecoveryV3ExactRecord(t *testing.T) {
	r := scopeRecoveryRecordFixtureV3()
	raw, err := EncodeRoutedScopeRecoveryV3(r)
	if err != nil || len(raw) != 4096 {
		t.Fatal(err)
	}
	got, err := DecodeRoutedScopeRecoveryV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	got.IntegritySHA256 = ""
	if got != r {
		t.Fatal("record changed")
	}
	for name, mutate := range map[string]func(*RoutedScopeRecoveryRecordV3){
		"host":           func(r *RoutedScopeRecoveryRecordV3) { r.Metadata.GatewayNamespace = r.Metadata.HostNamespace },
		"gateway":        func(r *RoutedScopeRecoveryRecordV3) { r.Gateway.Inode++ },
		"alias":          func(r *RoutedScopeRecoveryRecordV3) { r.Mount = r.Gateway },
		"zero":           func(r *RoutedScopeRecoveryRecordV3) { r.Cgroup.Inode = 0 },
		"missing_events": func(r *RoutedScopeRecoveryRecordV3) { r.CgroupEvents = RoutedScopeRecoveryFileV3{} },
		"aliased_events": func(r *RoutedScopeRecoveryRecordV3) { r.CgroupEvents = r.Cgroup },
		"hash":           func(r *RoutedScopeRecoveryRecordV3) { r.MetadataSHA256 = strings.Repeat("b", 64) },
		"retired":        func(r *RoutedScopeRecoveryRecordV3) { r.Phase = "retired" },
		"root_helper":    func(r *RoutedScopeRecoveryRecordV3) { r.Identities.HelperUID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if _, err := EncodeRoutedScopeRecoveryV3(changed); err == nil {
				t.Fatal("invalid record encoded")
			}
		})
	}
	for _, bad := range [][]byte{raw[:4095], append(append([]byte{}, raw...), byte(' ')), bytes.Replace(raw, []byte(`"pinned"`), []byte(`"closed"`), 1), bytes.Repeat([]byte{0}, 4096)} {
		if _, err := DecodeRoutedScopeRecoveryV3(bad); err == nil {
			t.Fatal("torn or changed record accepted")
		}
	}
}
