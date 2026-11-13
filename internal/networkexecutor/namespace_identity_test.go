package networkexecutor

import (
	"strings"
	"testing"
)

func TestOwnedNamespaceIdentityPortableValidation(t *testing.T) {
	valid := OwnedNamespaceIdentity{UID: 62001, GID: 62003, Namespace: 2, Host: 1, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc"}
	if !validOwnedIdentity(valid) {
		t.Fatal("valid format refused")
	}
	for _, change := range []func(*OwnedNamespaceIdentity){
		func(v *OwnedNamespaceIdentity) { v.UID = 0 }, func(v *OwnedNamespaceIdentity) { v.GID = 0 },
		func(v *OwnedNamespaceIdentity) { v.Namespace = 0 }, func(v *OwnedNamespaceIdentity) { v.Host = 0 },
		func(v *OwnedNamespaceIdentity) { v.Namespace = v.Host }, func(v *OwnedNamespaceIdentity) { v.RunID = "" },
		func(v *OwnedNamespaceIdentity) { v.RunID = strings.Repeat("A", 32) }, func(v *OwnedNamespaceIdentity) { v.RunID = strings.Repeat("z", 32) },
		func(v *OwnedNamespaceIdentity) { v.BootID = "" }, func(v *OwnedNamespaceIdentity) { v.BootID = strings.ToUpper(v.BootID) },
		func(v *OwnedNamespaceIdentity) { v.BootID = strings.ReplaceAll(v.BootID, "-", "_") },
	} {
		candidate := valid
		change(&candidate)
		if validOwnedIdentity(candidate) {
			t.Fatal("malformed identity accepted")
		}
	}
}
