package localtransport

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func status() []byte {
	return []byte("Name:\ttest\nUid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\nCapInh:\t0000000000001000\nCapPrm:\t0000000000001000\nCapEff:\t0000000000001000\nCapBnd:\t0000000000001000\nCapAmb:\t0000000000001000\nNoNewPrivs:\t1\n")
}

func TestOnlyNetAdminNonrootAndNoNewPrivileges(t *testing.T) {
	if e := privileges(status(), 1001, 1002); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(status()), "1001", "0", 1), strings.Replace(string(status()), "1002", "1003", 1), strings.Replace(string(status()), "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(string(status()), "0000000000001000", "0000000000201000", 1), strings.Replace(string(status()), "0000000000001000", "0000000000000000", 1), string(status()) + "CapEff:\t0000000000001000\n", strings.Replace(string(status()), "CapAmb:\t0000000000001000\n", "", 1)} {
		if privileges([]byte(bad), 1001, 1002) == nil {
			t.Fatal("unsafe privilege admitted", bad)
		}
	}
	if _, e := New(42, 42); e == nil {
		t.Fatal("host identity admitted")
	}
	if _, e := New(0, 1); e == nil {
		t.Fatal("missing namespace admitted")
	}
	file, e := os.Open("/dev/null")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	if _, e := namespaceInode(int(file.Fd())); e == nil {
		t.Fatal("ordinary fd accepted as namespace")
	}
}

func TestCommandsHaveOnlyFixedPathsAndArguments(t *testing.T) {
	cases := map[operation][]string{check: {"/usr/sbin/nft", "-j", "-c", "-f", "-"}, apply: {"/usr/sbin/nft", "-j", "-f", "-"}, listTables: {"/usr/sbin/nft", "-j", "list", "tables"}, listTable: {"/usr/sbin/nft", "-j", "list", "table", "inet", "andeiva_local"}}
	for op, want := range cases {
		cmd, e := command(context.Background(), op)
		if e != nil || cmd.Path != "/usr/sbin/nft" || !reflect.DeepEqual(cmd.Args, want) || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
			t.Fatal(op, cmd, e)
		}
		if !reflect.DeepEqual(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}) {
			t.Fatal("inherited environment")
		}
	}
	if _, e := command(context.Background(), 99); e == nil {
		t.Fatal("unknown operation")
	}
}

func TestOutputBufferStaysBoundedUnderConcurrentWrites(t *testing.T) {
	var b limitedBuffer
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _, _ = b.Write(bytes.Repeat([]byte("x"), MaxOutput/8)) })
	}
	wg.Wait()
	if b.Len() != MaxOutput || !b.failed() || len(b.Bytes()) != MaxOutput {
		t.Fatal("unbounded output", b.Len(), b.failed())
	}
	copy := b.Bytes()
	copy[0] = 'y'
	if b.Bytes()[0] != 'x' {
		t.Fatal("output alias")
	}
}

func TestNamespacePinMustExistBeforeOpeningProc(t *testing.T) {
	if mode := os.Getenv("ANDEIVA_TEST_NAMESPACE_PIN"); mode != "" {
		// Get the expected identity independently, then leave FD3 in the selected
		// state. Opening /proc inside verifyNamespace must never repair a hole.
		self, err := os.Open("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		current, err := namespaceInode(int(self.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = self.Close()
		if mode == "closed" {
			_ = syscall.Close(3)
		}
		err = verifyNamespace(current, current+1)
		if mode == "valid" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err != ErrIdentity {
			t.Fatal("unretained pin accepted", mode, err)
		}
		if mode == "closed" {
			if _, err := namespaceInode(3); err == nil {
				t.Fatal("verification recreated FD3")
			}
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"closed", "ordinary", "valid"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(self, "-test.run=^TestNamespacePinMustExistBeforeOpeningProc$")
			cmd.Env = []string{"ANDEIVA_TEST_NAMESPACE_PIN=" + mode}
			if mode != "closed" {
				path := "/dev/null"
				if mode == "valid" {
					path = "/proc/self/ns/net"
				}
				pin, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer pin.Close()
				cmd.ExtraFiles = []*os.File{pin}
			}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("subprocess %s: %v: %s", mode, err, output)
			}
		})
	}
}
