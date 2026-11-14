package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func verifyBundle(id string) error {
	if !hashRE.MatchString(id) {
		return errProfile
	}
	dir := filepath.Join(bundleBase, id)
	inventory, e := readFile(filepath.Join(dir, "SHA256SUMS"), 128<<10)
	if e != nil || sha(inventory) != id {
		return errProfile
	}
	expected := map[string]bool{"SHA256SUMS": true}
	previous := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(inventory), "\n"), "\n") {
		p := strings.Split(line, "  ")
		if len(p) != 2 || !hashRE.MatchString(p[0]) || p[1] <= previous || filepath.Clean(p[1]) != p[1] || strings.HasPrefix(p[1], "/") || strings.Contains(p[1], "..") || expected[p[1]] {
			return errProfile
		}
		previous = p[1]
		h, _, e := fileHash(filepath.Join(dir, p[1]), 256<<20)
		if e != nil || h != p[0] {
			return errProfile
		}
		expected[p[1]] = true
	}
	n := 0
	e = filepath.WalkDir(dir, func(path string, d os.DirEntry, e error) error { // #nosec G703 -- Fixed bundle root plus validated 64-hex ID; exact inventory and root-owned ancestors are verified.
		if e != nil {
			return e
		}
		if d.IsDir() {
			return secure(path, true)
		}
		rel, e := filepath.Rel(dir, path)
		if e != nil || !expected[rel] {
			return errProfile
		}
		n++
		return nil
	})
	if e != nil || n != len(expected) {
		return errProfile
	}
	for _, a := range archives() {
		h, n, e := fileHash(filepath.Join(dir, "archives", a.Leaf()), a.Size)
		if e != nil || n != a.Size || h != a.Hash {
			return errProfile
		}
	}
	sourceProfile, e := profileFS.ReadFile("profile/sources.tsv")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sourceProfile)), "\n")[1:] {
		p := strings.Split(line, "\t")
		if len(p) != 3 {
			return errProfile
		}
		size, e := strconv.ParseInt(p[2], 10, 64)
		if e != nil {
			return errProfile
		}
		h, n, e := fileHash(filepath.Join(dir, p[0]), size)
		if e != nil || n != size || h != p[1] {
			return errProfile
		}
	}
	return verifyProvenance(dir)
}

// Observe the real POSIX lock owned by APT. This does not acquire a different
// flock lock or purport to serialize with dpkg using our own lock implementation.
func aptOwnsLock() error {
	if os.Getenv("APT_HOOK_INFO_FD") != "0" || os.Getenv("DPKG_FRONTEND_LOCKED") != "true" {
		return errProfile
	}
	path := "/var/lib/dpkg/lock-frontend"
	if e := secure(path, false); e != nil {
		return e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if e := unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &lock); e != nil {
		return e
	}
	if lock.Type == unix.F_UNLCK || lock.Pid <= 1 {
		return errProfile
	}
	exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", lock.Pid))
	if e != nil || exe != "/usr/bin/apt-get" {
		return errProfile
	}
	return nil
}

func ownGuard() error {
	b, e := readFile(policy, 4096)
	if e != nil || string(b) != guard {
		return errProfile
	}
	var st unix.Stat_t
	if e := unix.Lstat(mask, &st); e != nil || st.Uid != 0 || st.Gid != 0 || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return errProfile
	}
	dest, e := os.Readlink(mask)
	if e != nil || dest != "/dev/null" {
		return errProfile
	}
	state, e := run("/usr/bin/systemctl", "show", unit, "--property=LoadState", "--property=MainPID", "--property=ActiveState")
	if e != nil || !bytes.Contains(state, []byte("LoadState=masked\n")) || !bytes.Contains(state, []byte("MainPID=0\n")) || !bytes.Contains(state, []byte("ActiveState=inactive\n")) {
		return errProfile
	}
	return nil
}

func hook(id, approval string) error {
	if !hashRE.MatchString(id) || !hashRE.MatchString(approval) {
		return errProfile
	}
	if e := aptOwnsLock(); e != nil {
		return e
	}
	stage := filepath.Join(stateDir, id)
	if e := secure(stage, true); e != nil {
		return e
	}
	if e := validatePlan(os.Stdin, filepath.Join(stage, "archives")); e != nil {
		return e
	}
	if e := verifyBundle(id); e != nil {
		return e
	}
	if e := noServer(); e != nil {
		return e
	}
	observed, e := capture()
	if e != nil || sha(observed) != approval {
		return fmt.Errorf("%w: reviewed capture changed", errProfile)
	}
	if e := create(filepath.Join(stage, "locked-preflight.json"), observed, 0600); e != nil {
		return e
	}
	// Retain protected original state, never replay it automatically over live files.
	for _, p := range []string{"/var/lib/dpkg/status", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/diversions", "/etc/passwd", "/etc/group"} {
		b, e := readFile(p, 8<<20)
		if e != nil {
			return e
		}
		if e := create(filepath.Join(stage, strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_")+".before"), b, 0600); e != nil {
			return e
		}
	}
	record, _ := json.Marshal(struct {
		Version                        int
		Bundle, ApprovedCapture, State string
	}{1, id, approval, "package-effects-pending"})
	if e := create(filepath.Join(stage, "pending.json"), record, 0600); e != nil {
		return e
	}
	// O_EXCL and symlink creation cannot overwrite a foreign start policy or mask.
	if e := create(policy, []byte(guard), 0755); e != nil {
		return e
	}
	if e := os.Symlink("/dev/null", mask); e != nil {
		return e
	}
	if e := syncDir(filepath.Dir(mask)); e != nil {
		return e
	}
	if _, e := run("/usr/bin/systemctl", "daemon-reload"); e != nil {
		return e
	}
	if e := ownGuard(); e != nil {
		return e
	}
	return create(filepath.Join(stage, "unpack-authorized"), []byte("1\n"), 0600)
}

func aptConfig(stage, bundle, id, approval string) string {
	hookCmd := bundle + "/bin/check"
	return fmt.Sprintf(`Dir::Etc "%[1]s/empty";
Dir::Etc::main "/dev/null";
Dir::Etc::parts "%[1]s/empty";
Dir::Etc::sourcelist "/dev/null";
Dir::Etc::sourceparts "%[1]s/empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "%[1]s/empty";
Dir::State::lists "%[1]s/lists";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache::archives "%[1]s/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "%[1]s/log";
Dir::Log::Terminal "/dev/null";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::Languages "none";
DPkg::Use-Pty "false";
DPkg::Lock::Timeout "0";
DPkg::Pre-Install-Pkgs { "%[2]s hook %[3]s %[4]s"; };
DPkg::Tools::Options::%[2]s::Version "3";
DPkg::Tools::Options::%[2]s::InfoFD "0";
`, stage, hookCmd, id, approval)
}

func install(id, approval string) error {
	if e := installerUnit(false); e != nil {
		return e
	}
	for _, path := range []string{"/", "/var/lib/dpkg", "/var/backups"} {
		var st unix.Statfs_t
		if e := unix.Statfs(path, &st); e != nil {
			return e
		}
		if st.Bsize <= 0 || st.Bsize > 1<<20 || st.Bavail < (512<<20)/uint64(st.Bsize) || st.Ffree < 4096 {
			return fmt.Errorf("%w: minimum free-space/inode reserve", errProfile)
		}
	}
	if !hashRE.MatchString(approval) {
		return errProfile
	}
	if e := verifyBundle(id); e != nil {
		return e
	}
	observed, e := capture()
	if e != nil || sha(observed) != approval {
		return fmt.Errorf("%w: approved capture required", errProfile)
	}
	if e := secure("/var/backups", true); e != nil {
		return e
	}
	if e := os.Mkdir(stateDir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e := secure(stateDir, true); e != nil {
		return e
	}
	entries, e := os.ReadDir(stateDir)
	if e != nil || len(entries) != 0 {
		return fmt.Errorf("%w: retained operation requires review", errProfile)
	}
	if e := create(filepath.Join(stateDir, "install-pending"), []byte(id+"\n"), 0600); e != nil {
		return e
	}
	stage := filepath.Join(stateDir, id)
	if e := os.Mkdir(stage, 0700); e != nil { // #nosec G703 -- Stage is a validated 64-hex ID under the checked fixed state root.
		return e
	}
	if e := syncDir(stateDir); e != nil {
		return e
	}
	if e := create(filepath.Join(stage, "approved-capture.json"), observed, 0600); e != nil {
		return e
	}
	for _, d := range []string{"empty", "archives", "lists", "lists/partial", "log"} {
		if e := os.Mkdir(filepath.Join(stage, d), 0700); e != nil { // #nosec G703 -- Only literal internal directory names are joined to the exclusively created stage.
			return e
		}
	}
	bundle := filepath.Join(bundleBase, id)
	args := []string{"--assume-yes", "--no-download", "--no-remove", "--no-upgrade", "--no-install-recommends", "install"}
	for _, a := range archives() {
		b, e := readFile(filepath.Join(bundle, "archives", a.Leaf()), a.Size)
		if e != nil {
			return e
		}
		target := filepath.Join(stage, "archives", a.Leaf())
		if e := create(target, b, 0600); e != nil {
			return e
		}
		args = append(args, target)
	}
	if e := create(filepath.Join(stage, "apt.conf"), []byte(aptConfig(stage, bundle, id, approval)), 0600); e != nil {
		return e
	}
	// Native APT owns its normal POSIX frontend/dpkg locks throughout this action.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/apt-get", args...) // #nosec G702 -- Fixed APT executable/options and embedded archive names beneath the validated fixed-root stage; no shell.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "APT_CONFIG=" + filepath.Join(stage, "apt.conf")}
	cmd.WaitDelay = 3 * time.Second
	logFile, e := os.OpenFile(filepath.Join(stage, "apt.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G703 G304 -- Literal log name under the private exclusive stage; existing entries cannot be replaced.
	if e != nil {
		return e
	}
	defer logFile.Close()
	if e := logFile.Sync(); e != nil {
		return e
	}
	if e := syncDir(stage); e != nil {
		return e
	}
	output := &durableLog{file: logFile}
	cmd.Stdout = output
	cmd.Stderr = output
	e = cmd.Run()
	logErr := logFile.Sync()
	if e != nil || logErr != nil || output.failed || output.overflow {
		return fmt.Errorf("%w: installation incomplete; retain guard and evidence", errProfile)
	}
	if b, e := readFile(filepath.Join(stage, "unpack-authorized"), 16); e != nil || string(b) != "1\n" {
		return errProfile
	}
	if e := ownGuard(); e != nil {
		return e
	}
	status, e := readFile("/var/lib/dpkg/status", 8<<20)
	if e != nil || baseline(status, true) != nil {
		return errProfile
	}
	before, e := readFile(filepath.Join(stage, "var_lib_dpkg_status.before"), 8<<20)
	if e != nil || unchangedOtherPackages(before, status) != nil {
		return errProfile
	}
	audit, e := run("/usr/bin/dpkg", "--audit")
	if e != nil || len(audit) != 0 {
		return errProfile
	}
	if _, e := run("/usr/bin/systemctl", "disable", unit); e != nil {
		return e
	}
	if _, e := run("/usr/sbin/update-rc.d", "kea-dhcp4-server", "disable"); e != nil {
		return e
	}
	if e := ownGuard(); e != nil {
		return e
	}
	if e := noServer(); e != nil {
		return e
	}
	if e := installerUnit(true); e != nil {
		return e
	}
	// Intentionally retain both guards. Separate reviewed activation/recovery must
	// inspect this receipt; this installer never enables the module or unblocks it.
	return create(filepath.Join(stage, "installed-inactive.json"), []byte("{\"version\":1,\"state\":\"installed-inactive\",\"guard_retained\":true}\n"), 0600)
}

// The caller's dedicated systemd unit owns all package-manager descendants. A
// timeout here is incomplete, never evidence of child drainage; the outer caller
// must wait for the unit's control group to become empty before recovery.
func installerUnit(drained bool) error {
	const name = "andeiva-dhcp-offline-install.service"
	const group = "/system.slice/" + name
	data, e := run("/usr/bin/systemctl", "show", name, "--property=MainPID", "--property=ControlGroup", "--property=KillMode", "--property=Delegate", "--property=SendSIGKILL", "--property=RemainAfterExit", "--property=InvocationID")
	if e != nil {
		return e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 || fields[p[0]] != "" {
			return errProfile
		}
		fields[p[0]] = p[1]
	}
	if fields["MainPID"] != strconv.Itoa(os.Getpid()) || fields["ControlGroup"] != group || fields["KillMode"] != "control-group" || fields["Delegate"] != "no" || fields["SendSIGKILL"] != "yes" || fields["RemainAfterExit"] != "yes" || len(fields["InvocationID"]) != 32 || !hashRE.MatchString(fields["InvocationID"]+fields["InvocationID"]) {
		return fmt.Errorf("%w: dedicated installer unit required", errProfile)
	}
	current, e := os.ReadFile("/proc/self/cgroup")
	if e != nil || string(current) != "0::"+group+"\n" {
		return errProfile
	}
	var st unix.Statfs_t
	if e := unix.Statfs("/sys/fs/cgroup"+group, &st); e != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		return errProfile
	}
	if drained {
		pids, e := os.ReadFile("/sys/fs/cgroup" + group + "/cgroup.procs")
		if e != nil || strings.TrimSpace(string(pids)) != strconv.Itoa(os.Getpid()) {
			return fmt.Errorf("%w: package descendants remain", errProfile)
		}
	}
	return nil
}

func noServer() error {
	processes, e := os.ReadDir("/proc")
	if e != nil {
		return e
	}
	for _, p := range processes {
		if _, e := strconv.Atoi(p.Name()); e != nil {
			continue
		}
		b, e := os.ReadFile(filepath.Join("/proc", p.Name(), "comm"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if strings.HasPrefix(string(b), "kea-") {
			return errProfile
		}
	}
	for _, p := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, e := os.ReadFile(p) // #nosec G304 -- The loop contains only the fixed kernel paths /proc/net/udp and /proc/net/udp6.
		if e != nil {
			return e
		}
		for i, l := range strings.Split(string(b), "\n") {
			if i == 0 || l == "" {
				continue
			}
			f := strings.Fields(l)
			if len(f) < 3 {
				return errProfile
			}
			if strings.HasSuffix(f[1], ":0043") {
				return errProfile
			}
		}
	}
	return nil
}

func runMain() error {
	if os.Geteuid() != 0 {
		return errProfile
	}
	switch {
	case len(os.Args) == 2 && os.Args[1] == "capture":
		if e := noServer(); e != nil {
			return e
		}
		b, e := capture()
		if e != nil {
			return e
		}
		_, e = os.Stdout.Write(b)
		return e
	case len(os.Args) == 4 && os.Args[1] == "install":
		return install(os.Args[2], os.Args[3])
	case len(os.Args) == 4 && os.Args[1] == "hook":
		return hook(os.Args[2], os.Args[3])
	case len(os.Args) == 3 && os.Args[1] == "verify":
		return verifyBundle(os.Args[2])
	default:
		return errProfile
	}
}
func main() {
	if e := runMain(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

type durableLog struct {
	file             *os.File
	written          int
	failed, overflow bool
}

func (l *durableLog) Write(p []byte) (int, error) {
	n := len(p)
	left := (4 << 20) - l.written
	if len(p) > left {
		p = p[:left]
		l.overflow = true
	}
	if !l.failed {
		w, e := l.file.Write(p)
		l.written += w
		if e != nil || w != len(p) {
			l.failed = true
		}
	}
	return n, nil
}
