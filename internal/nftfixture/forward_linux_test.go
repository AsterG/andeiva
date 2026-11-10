package nftfixture

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
)

func TestForwardRoleRejectsMissingInheritedDescriptor(t *testing.T) {
	if os.Getenv("ANDEIVA_TEST_MISSING_GATEWAY_FD") == "1" {
		if syscall.Close(3) != nil {
			os.Exit(2)
		}
		err := enableForwarding(1)
		if err == nil || err.Error() != "ANDEIVA_NFT_FIXTURE_NAMESPACE_DESCRIPTOR" {
			os.Exit(3)
		}
		return
	}
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestForwardRoleRejectsMissingInheritedDescriptor$")
	cmd.Env = append(os.Environ(), "ANDEIVA_TEST_MISSING_GATEWAY_FD=1")
	cmd.ExtraFiles = []*os.File{ns, ns}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("missing descriptor guard: %v: %s", err, output)
	}
}

func TestForwardIdentityRejectsSwappedOrInconsistentNamespaces(t *testing.T) {
	if !validForwardIdentity(42, 43, 43, 42) {
		t.Fatal("isolated pinned gateway rejected")
	}
	for _, ids := range [][4]uint64{{42, 43, 42, 43}, {42, 42, 42, 42}, {42, 44, 43, 42}, {41, 43, 43, 42}, {42, 0, 0, 42}} {
		if validForwardIdentity(ids[0], ids[1], ids[2], ids[3]) {
			t.Fatal("swapped or inconsistent namespace accepted")
		}
	}
}

func TestForwardNamespaceDescriptorsFailClosed(t *testing.T) {
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	id, err := networkNamespaceInode(int(ns.Fd()))
	if err != nil || id == 0 {
		t.Fatalf("network descriptor: %d %v", id, err)
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mount.Close()
	closed, err := syscall.Dup(int(ns.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(closed); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{-1, closed, int(regular.Fd()), int(mount.Fd())} {
		if _, err := networkNamespaceInode(fd); err == nil {
			t.Fatalf("accepted invalid network descriptor %d", fd)
		}
		for slot := 0; slot < 3; slot++ {
			fds := [3]int{int(ns.Fd()), int(ns.Fd()), int(ns.Fd())}
			fds[slot] = fd
			if validateForwardNamespaces(id, fds[0], fds[1], fds[2]) == nil {
				t.Fatal("invalid descriptor permitted forwarding")
			}
		}
	}
	for _, expected := range []uint64{0, id, id + 1} {
		if validateForwardNamespaces(expected, int(ns.Fd()), int(ns.Fd()), int(ns.Fd())) == nil {
			t.Fatal("same namespace or inconsistent host permitted forwarding")
		}
	}
}

func TestForwardCommandRequiresRetainedHostDescriptor(t *testing.T) {
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	id, err := networkNamespaceInode(int(ns.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	f := &Fixture{self: "/fixture", host: id + 1, namespaces: map[string]*namespace{"gateway": {handle: ns, inode: id}}}
	args := []string{"--nft-fixture", "forward", strconv.FormatUint(f.host, 10)}
	if _, err := f.command(context.Background(), "gateway", f.self, args, "", false, false); err == nil {
		t.Fatal("missing host descriptor accepted")
	}
	f.hostHandle = ns
	if _, err := f.command(context.Background(), "gateway", f.self, args, "", false, false); err == nil {
		t.Fatal("inconsistent host descriptor accepted")
	}
}

func TestOwnedCleanupClosesRetainedHostDescriptor(t *testing.T) {
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	f := &Fixture{hostHandle: ns}
	if err := f.CloseOwned(); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.Stat(); err == nil {
		t.Fatal("retained host descriptor not closed")
	}
}
