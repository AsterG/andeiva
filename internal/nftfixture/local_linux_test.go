package nftfixture

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestLocalSetupNeverEnablesTransit(t *testing.T) {
	f := &Fixture{self: "/fixture", host: 42, uid: 1001, gid: 1001, localOnly: true}
	addresses, links, sentinel := 0, 0, 0
	for _, plan := range f.setupCommands() {
		joined := strings.Join(plan.args, " ")
		if strings.Contains(joined, "route") || strings.Contains(joined, "forward") || strings.Contains(joined, "ens33") || strings.Contains(joined, "ens34") || plan.binary == f.self {
			t.Fatal("transit or host setup", plan)
		}
		if !f.allowedCommand(plan.role, plan.binary, plan.args, plan.peer, false, false) {
			t.Fatal("plan denied", plan)
		}
		if f.allowedCommand("host", plan.binary, plan.args, plan.peer, false, false) || f.allowedCommand(plan.role, "/bin/sh", plan.args, plan.peer, false, false) {
			t.Fatal("scope expansion", plan)
		}
		if slices.Contains(plan.args, "address") {
			addresses++
			if plan.args[0] == "-6" && !slices.Contains(plan.args, "nodad") {
				t.Fatal("DAD setup race")
			}
		}
		if slices.Contains(plan.args, "addrgenmode") {
			links++
			if plan.args[len(plan.args)-1] != "none" {
				t.Fatal("random link local")
			}
		}
		if plan.binary == nftPath {
			sentinel++
			if plan.input != "add table inet andeiva_sentinel\n" {
				t.Fatal("unexpected nft setup")
			}
		}
	}
	if addresses != 16 || links != 4 || sentinel != 1 {
		t.Fatal("incomplete dual-stack setup", addresses, links, sentinel)
	}
	forward := []string{"--nft-fixture", "forward", "42"}
	if f.allowedCommand("gateway", f.self, forward, "", false, false) || f.allowedCommand("gateway", nftPath, []string{"-j", "-f", "-"}, "", false, false) {
		t.Fatal("legacy mutations admitted in local mode")
	}
	for _, role := range []string{"source", "sink"} {
		if f.allowedCommand(role, f.self, []string{"--nft-fixture", "probe", "tcp", "18080", "42"}, "", true, false) {
			t.Fatal("transit probe admitted")
		}
	}
	f.localOnly = false
	found := false
	for _, plan := range f.setupCommands() {
		if slices.Equal(plan.args, forward) {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy forwarding behavior changed")
	}
}

func TestLocalRolesAreUnprivilegedAndBoundToSupervisor(t *testing.T) {
	f := &Fixture{self: "/fixture", host: 42, uid: 1001, gid: 1001, localOnly: true}
	args := []string{"--local-services", "42", strconv.Itoa(os.Getpid())}
	if !f.allowedCommand("gateway", f.self, args, "", true, false) {
		t.Fatal("runtime denied")
	}
	for _, role := range []string{"source", "sink", "host"} {
		if f.allowedCommand(role, f.self, args, "", true, false) {
			t.Fatal("runtime wrong namespace")
		}
	}
	if f.allowedCommand("gateway", f.self, args, "", false, false) || f.allowedCommand("gateway", f.self, args, "", true, true) || f.allowedCommand("gateway", f.self, args, "source", true, false) {
		t.Fatal("runtime privilege/descriptor expansion")
	}
	for _, bad := range [][]string{{"--local-services", "43", args[2]}, {"--local-services", "42", "1"}, {"--local-services", "42", args[2], "sh"}} {
		if f.allowedCommand("gateway", f.self, bad, "", true, false) {
			t.Fatal("unbound runtime", bad)
		}
	}
	for _, side := range []string{"source", "sink"} {
		p := LocalProbe{side, "ipv6", "alternate", "udp", 18082}
		probe, _ := localProbeArgs(p, 42)
		if !f.allowedCommand(side, f.self, probe, "", true, false) || f.allowedCommand("gateway", f.self, probe, "", true, false) || f.allowedCommand(side, f.self, probe, "", true, true) {
			t.Fatal("probe isolation")
		}
	}
	f.localOnly = false
	if f.allowedCommand("gateway", f.self, args, "", true, false) {
		t.Fatal("local runtime in transit mode")
	}
	if _, err := f.StartLocalServices(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("mode guard missing")
	}
	if err := f.StartLocalEcho(context.Background()); err == nil {
		t.Fatal("echo mode guard missing")
	}
}

func TestLocalServiceCommandPinsNamespaceAndDropsCapabilities(t *testing.T) {
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
	f := &Fixture{self: "/fixture", host: id + 1, uid: 1001, gid: 1001, localOnly: true, namespaces: map[string]*namespace{"gateway": {handle: file, inode: id}}}
	cmd, err := f.command(context.Background(), "gateway", f.self, []string{"--local-services", strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())}, "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "--net=/proc/self/fd/3") || !strings.Contains(joined, "--bounding-set=-all") || strings.Contains(joined, "+net_admin") || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != file {
		t.Fatal("privilege contract", cmd.Args)
	}
	if GuardLocalServices(0, 1) == nil {
		t.Fatal("unbound runtime guard")
	}
}

func TestColdNeighborOperationCannotExpandBeyondOwnedVeths(t *testing.T) {
	f := &Fixture{self: "/fixture", host: 42, uid: 1001, gid: 1001, localOnly: true}
	commands := localNeighborCommands()
	if len(commands) != 8 {
		t.Fatal("missing family/interface operation")
	}
	for _, plan := range commands {
		if !f.allowedCommand(plan.role, plan.binary, plan.args, "", false, false) {
			t.Fatal("fixed cache clear denied")
		}
		if f.allowedCommand("host", plan.binary, plan.args, "", false, false) || f.allowedCommand(plan.role, plan.binary, plan.args, "", true, true) {
			t.Fatal("scope/capability expansion")
		}
		bad := append([]string{}, plan.args...)
		bad[len(bad)-1] = "ens33"
		if f.allowedCommand(plan.role, plan.binary, bad, "", false, false) {
			t.Fatal("host cache clear accepted")
		}
	}
	f.localOnly = false
	for _, plan := range commands {
		if f.allowedCommand(plan.role, plan.binary, plan.args, "", false, false) {
			t.Fatal("cache clear in legacy mode")
		}
	}
	if err := f.ClearLocalNeighbors(context.Background()); err == nil {
		t.Fatal("mode guard")
	}
}
