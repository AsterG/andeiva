package localtransport

import (
	"bytes"
	"context"
	"os"
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
