//go:build linux

package previewruntime

import (
	"context"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRoutedIntegrityLaunchV3PrivateDirectory(t *testing.T) {
	area, uid, gid := integrityFenceFixtureV3(t)
	file, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateRoutedIntegrityDirectoryV3(file, uid, gid, nil); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if validateRoutedIntegrityDirectoryV3(file, uid, gid, []os.FileInfo{info}) == nil {
		t.Fatal("aliased root accepted")
	}
	if validateRoutedIntegrityDirectoryV3(file, uid+1, gid, nil) == nil || validateRoutedIntegrityDirectoryV3(file, uid, gid+1, nil) == nil {
		t.Fatal("foreign identity accepted")
	}
	if err := os.Chmod(area.Name(), 0750); err != nil {
		t.Fatal(err)
	}
	if validateRoutedIntegrityDirectoryV3(file, uid, gid, nil) == nil {
		t.Fatal("shared private root accepted")
	}
	if err := os.Chmod(area.Name(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fsetxattr(int(file.Fd()), "user.test", []byte("bounded"), 0); err != nil {
		t.Fatal(err)
	}
	// An unrelated xattr does not widen POSIX access.
	if validateRoutedIntegrityDirectoryV3(file, uid, gid, nil) != nil {
		t.Fatal("unrelated xattr changed authority")
	}
	// This explicit supervisor entry point never elevates an unprivileged caller.
	if err := PrepareRoutedIntegrityLaunchV3(context.Background(), Identities{}, area, nil); err == nil {
		t.Fatal("invalid installer scope accepted")
	}
	if err := RunRoutedIntegrityPrepareRoleV3(nil); err == nil {
		t.Fatal("missing trusted context accepted")
	}
}

func TestRoutedIntegrityLaunchV3CaplessPrepareProfile(t *testing.T) {
	status := "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if err := routedIntegrityPrepareProcessV3(1001, 1001, 1002, 1002, nil, status, 1001, 1002); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(status, "CapEff:\t0000000000000000", "CapEff:\t0000000000001000", 1), status + "CapEff:\t0000000000000000\n", strings.Repeat("x", 65537)} {
		if routedIntegrityPrepareProcessV3(1001, 1001, 1002, 1002, nil, bad, 1001, 1002) == nil {
			t.Fatal("privileged/malformed preparation profile accepted")
		}
	}
	if routedIntegrityPrepareProcessV3(1001, 1001, 1002, 1002, []int{1003}, status, 1001, 1002) == nil || routedIntegrityPrepareProcessV3(1001, 0, 1002, 1002, nil, status, 1001, 1002) == nil {
		t.Fatal("foreign process accepted")
	}
	// The API context carries only the trusted modality, never the private root.
	f := &routedLaunchFilesV3{}
	b := routedLaunchBootstrapV3{Integrity: true}
	if c := f.context(b); !c.Integrity || c.IntegrityRoot != nil {
		t.Fatal("API context gained private root")
	}
}
