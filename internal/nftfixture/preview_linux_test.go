package nftfixture

import (
	"context"
	"os"
	"testing"
)

func TestPreviewCloseOwnedReleasesRetainedDescriptors(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	f := &Fixture{namespaces: map[string]*namespace{"gateway": {handle: read, input: write, inode: 17}}}
	if err = f.CloseOwned(); err != nil {
		t.Fatal(err)
	}
	if _, err = read.Stat(); err == nil {
		t.Fatal("retained namespace descriptor stayed open")
	}
	if _, err = write.Write([]byte("x")); err == nil {
		t.Fatal("retained control pipe stayed open")
	}
	if err = f.CloseOwned(); err != nil {
		t.Fatal("owned cleanup is not idempotent")
	}
}

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
