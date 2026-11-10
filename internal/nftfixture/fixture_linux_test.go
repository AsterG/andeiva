package nftfixture

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestPrivilegePlanDropsAllUnneededCapabilities(t *testing.T) {
	plain := strings.Join(privilegeArgs(1000, 1001, false), " ")
	if strings.Contains(plain, "+net_admin") || !strings.Contains(plain, "--bounding-set=-all") || !strings.Contains(plain, "--no-new-privs") || !strings.Contains(plain, "--clear-groups") {
		t.Fatal(plain)
	}
	netAdmin := strings.Join(privilegeArgs(1000, 1001, true), " ")
	if strings.Count(netAdmin, "-all,+net_admin") != 3 || strings.Contains(netAdmin, "sys_admin") {
		t.Fatal(netAdmin)
	}
}

func TestReverseTrafficCommandsRemainFixedToOwnedEndpoints(t *testing.T) {
	f := &Fixture{self: "/fixture", host: 42, uid: 1001, gid: 1001}
	for _, role := range []string{"source", "sink"} {
		for _, protocol := range []string{"tcp", "udp"} {
			args := []string{"--nft-fixture", "probe-source", protocol, "18080", "42"}
			if !f.allowedCommand(role, f.self, args, "", true, false) {
				t.Fatal("reverse probe rejected")
			}
			if f.allowedCommand("gateway", f.self, args, "", true, false) || f.allowedCommand(role, f.self, args, "", true, true) {
				t.Fatal("reverse privilege expansion")
			}
			args[3] = "22"
			if f.allowedCommand(role, f.self, args, "", true, false) {
				t.Fatal("arbitrary port accepted")
			}
		}
	}
	args := []string{"--nft-fixture", "listen-source", "42"}
	if !f.allowedCommand("source", f.self, args, "", true, false) || f.allowedCommand("sink", f.self, args, "", true, false) {
		t.Fatal("listener endpoint expansion")
	}
}

func TestNamespaceGuardRejectsHostAndUnownedRoles(t *testing.T) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	id := info.Sys().(*syscall.Stat_t).Ino
	f := &Fixture{host: id, namespaces: map[string]*namespace{"gateway": {handle: file, inode: id}}}
	if _, err := f.checked("gateway"); err == nil {
		t.Fatal("accepted host namespace")
	}
	if _, err := f.checked("../host"); err == nil {
		t.Fatal("accepted unowned role")
	}
	f.host = id + 1
	f.namespaces["gateway"].inode = id + 2
	if _, err := f.checked("gateway"); err == nil {
		t.Fatal("accepted changed inode")
	}
	f.namespaces["gateway"].inode = id
	f.closed = true
	if _, err := f.checked("gateway"); err == nil {
		t.Fatal("accepted closed fixture")
	}
}

func TestCommandPlanPinsNamespaceBeforeFixedExecutable(t *testing.T) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	id := info.Sys().(*syscall.Stat_t).Ino
	f := &Fixture{self: "/fixture", host: id + 1, uid: 1000, gid: 1000, namespaces: map[string]*namespace{"gateway": {handle: file, inode: id}}}
	cmd, err := f.command(context.Background(), "gateway", f.self, []string{"--guardian", strings.Repeat("a", 32), strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())}, "", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != enterPath || !reflect.DeepEqual(cmd.Args[1:3], []string{"--net=/proc/self/fd/3", "--"}) || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != file {
		t.Fatalf("unexpected command: %v", cmd.Args)
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("missing parent-death signal")
	}
}

func TestFixtureCommandAllowlistRejectsScopeExpansion(t *testing.T) {
	f := &Fixture{self: "/fixture", host: 42, uid: 1000, gid: 1000}
	for _, plan := range f.setupCommands() {
		if !f.allowedCommand(plan.role, plan.binary, plan.args, plan.peer, false, false) {
			t.Fatalf("setup plan denied: %+v", plan)
		}
		if f.allowedCommand("host", plan.binary, plan.args, plan.peer, false, false) || f.allowedCommand(plan.role, "/bin/sh", plan.args, plan.peer, false, false) || f.allowedCommand(plan.role, plan.binary, append(append([]string{}, plan.args...), "extra"), plan.peer, false, false) {
			t.Fatalf("expanded plan accepted: %+v", plan)
		}
	}
	guardian := []string{"--guardian", strings.Repeat("b", 32), "42", strconv.Itoa(os.Getpid())}
	if !f.allowedCommand("gateway", f.self, guardian, "", true, true) {
		t.Fatal("guardian denied")
	}
	for i, value := range []string{"--run-lab", "../arbitrary", "0", "1"} {
		args := append([]string{}, guardian...)
		args[i] = value
		if f.allowedCommand("gateway", f.self, args, "", true, true) {
			t.Fatalf("invalid guardian accepted: %v", args)
		}
	}
	for _, role := range []string{"source", "sink"} {
		for _, protocol := range []string{"tcp", "udp"} {
			for port := 18080; port <= 18082; port++ {
				args := []string{"--nft-fixture", "probe", protocol, strconv.Itoa(port), "42"}
				if !f.allowedCommand(role, f.self, args, "", true, false) || f.allowedCommand(role, f.self, args, "", true, true) {
					t.Fatal("probe privilege boundary")
				}
			}
		}
	}
	if _, err := f.run(context.Background(), "gateway", nftPath, []string{"-f", "-"}, "", "flush ruleset\n"); err == nil {
		t.Fatal("arbitrary nft input accepted")
	}
}

func TestCommandOutputIsBounded(t *testing.T) {
	var output boundedBuffer
	if _, err := output.Write(bytes.Repeat([]byte{'x'}, 1024*1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("output exceeded bound")
	}
	if output.Len() != 1024*1024 {
		t.Fatal("buffer grew beyond bound")
	}
}

func TestHostQueriesAllowOnlyReadOperations(t *testing.T) {
	queries := map[string][]string{
		"rules":   {"/usr/sbin/nft", "-s", "-j", "list", "ruleset"},
		"routes":  {"/usr/bin/ip", "-j", "route", "show", "table", "all"},
		"routes6": {"/usr/bin/ip", "-6", "-j", "route", "show", "table", "all"},
		"links":   {"/usr/bin/ip", "-j", "link", "show"},
	}
	for key, want := range queries {
		cmd, err := hostReadCommand(context.Background(), key)
		if err != nil || !reflect.DeepEqual(cmd.Args, want) {
			t.Fatalf("unexpected host query %s: %v %v", key, cmd, err)
		}
	}
	for _, key := range []string{"", "flush ruleset", "route add", "/usr/bin/ip", "links;reboot"} {
		if cmd, err := hostReadCommand(context.Background(), key); err == nil || cmd != nil {
			t.Fatalf("accepted host command %q", key)
		}
	}
}
