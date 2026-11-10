package nftfixture

import (
	"context"
	"testing"
)

func TestPreviewPinAndDenyRejectMissingOrHostNamespace(t *testing.T) {
	for _, f := range []*Fixture{{}, {closed: true}, {host: 1, namespaces: map[string]*namespace{"gateway": {inode: 1}}}} {
		if e := f.PinPreviewGateway(); e == nil {
			t.Fatal("unowned namespace pin accepted")
		}
		if e := f.SealAdminDeny(context.Background()); e == nil {
			t.Fatal("unowned namespace policy accepted")
		}
	}
}

func TestPreviewDenyCommandCannotExpandRoleOrExecutable(t *testing.T) {
	f := &Fixture{}
	for _, v := range []struct {
		role, binary string
		args         []string
	}{{"source", nftPath, []string{"-j", "-f", "-"}}, {"gateway", "/bin/sh", []string{"-j", "-f", "-"}}, {"gateway", nftPath, []string{"flush", "ruleset"}}} {
		if f.allowedCommand(v.role, v.binary, v.args, "", false, false) {
			t.Fatal("expanded command accepted")
		}
	}
}
