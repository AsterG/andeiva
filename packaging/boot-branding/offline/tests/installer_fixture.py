#!/usr/bin/env python3
"""Exercise the real shell flow with filesystem/OS boundaries replaced in tests only.

No APT install, mount, namespace or host path is executed by these fixtures.
Signature verification and native namespace behavior are separate gates.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

IDENTIFIER = "a" * 64
PACKAGES = [("andeiva-boot-branding", "all"), ("andeiva-boot-activation", "amd64")]
VERSION = "0.1.0~alpha901"


def mock_command():
    root = Path(os.environ["ANDEIVA_FIXTURE_ROOT"])
    name, args = Path(sys.argv[0]).name, sys.argv[1:]
    installed = (root / "installed").exists()
    if name == "check":
        if args[0] == "verify":
            print(IDENTIFIER)
        else:
            os.execv(os.environ["ANDEIVA_FIXTURE_CHECK"], ["check", *args])
    elif name == "andeiva-boot-activation":
        print(json.dumps({"offline_install_guard": int(os.environ.get("ANDEIVA_FIXTURE_GUARD", "1"))}))
    elif name == "dpkg":
        if args == ["--print-architecture"]:
            print("amd64")
        elif args == ["--audit"] and os.environ.get("ANDEIVA_FIXTURE_DPKG_BAD"):
            print("fixture incomplete package")
    elif name == "dpkg-query":
        if not installed:
            sys.exit(1)
        package = args[-1]
        arch = dict(PACKAGES)[package]
        if args[-2] == "-f=${db:Status-Status}":
            print("installed")
        else:
            print(f"installed\t{VERSION}\t{arch}")
    elif name == "dpkg-deb":
        index = int(Path(args[-1]).stem) - 1
        package, arch = PACKAGES[index]
        print(f"{package}\t{VERSION}\t{arch}")
    elif name == "df":
        print("Available\n10000000000")
    elif name == "findmnt":
        field = args[args.index("-o") + 1]
        print({"FSTYPE": os.environ.get("ANDEIVA_FIXTURE_FSTYPE", "ext4"), "TARGET": "/", "PROPAGATION": "private", "VFS-OPTIONS": "ro"}[field])
    elif name == "uname":
        print("6.12.1-fixture")
    elif name == "readlink":
        print("mnt:[2]" if os.environ.get("ANDEIVA_FIXTURE_CHILD") else "mnt:[1]")
    elif name == "mount":
        if args[0] == "--bind":
            shutil.copyfile(args[1], args[2])
    elif name == "unshare":
        policy = root / "etc/initramfs-tools/update-initramfs.conf"
        before = policy.read_bytes()
        child_env = dict(os.environ, ANDEIVA_FIXTURE_CHILD="1")
        (root / "namespace-started").touch()
        time.sleep(float(os.environ.get("ANDEIVA_FIXTURE_DELAY", "0")))
        try:
            code = subprocess.run(args[3:], env=child_env, check=False).returncode
        finally:
            policy.write_bytes(before)
        sys.exit(code)
    elif name == "apt-get":
        config = Path(os.environ["APT_CONFIG"])
        text = config.read_text()
        if not config.is_relative_to(root) or 'Dir::Etc::main "/dev/null";' not in text:
            sys.exit(80)
        if 'Dir::Log::Terminal "/dev/null";' not in text:
            sys.exit(84)
        if "--no-download" not in args or "--no-upgrade" not in args or "--no-remove" not in args:
            sys.exit(81)
        if "-s" in args:
            for package, arch in PACKAGES:
                print(f"Inst {package} ({VERSION} local-deb [{arch}])")
            sys.exit(0)
        marker = root / "var/backups/andeiva-boot-offline/install-pending"
        if marker.read_text().strip() != IDENTIFIER or marker.stat().st_mode & 0o777 != 0o600:
            sys.exit(82)
        policy = root / "etc/initramfs-tools/update-initramfs.conf"
        if policy.read_text() != "update_initramfs=no\n":
            sys.exit(83)
        (root / "apt-started").touch()
        time.sleep(float(os.environ.get("ANDEIVA_FIXTURE_DELAY", "0")))
        if os.environ.get("ANDEIVA_FIXTURE_FAIL"):
            sys.exit(42)
        print("APT_STDOUT_FIXTURE")
        print("APT_STDERR_FIXTURE", file=sys.stderr)
        if os.environ.get("ANDEIVA_FIXTURE_FLOOD"):
            sys.stdout.write("A" * (4 * 1024 * 1024))
            sys.stderr.write("B" * 1024)
        if os.environ.get("ANDEIVA_FIXTURE_HOLD_PIPE"):
            subprocess.Popen(["/bin/sleep", "10"], stdin=subprocess.DEVNULL)
        (root / "installed").touch()
        if os.environ.get("ANDEIVA_FIXTURE_BOOT_DRIFT"):
            (root / "boot/vmlinuz-6.12.1-fixture").write_text("unexpected boot mutation\n")
        activator = root / "usr/sbin/andeiva-boot-activation"
        if not activator.exists():
            shutil.copyfile(Path(sys.argv[0]).resolve(), activator)
            activator.chmod(0o700)
        (root / "apt-finished").touch()
    elif name != "sync":
        raise RuntimeError(name)


class InstallerFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory(prefix="andeiva-fixture-check-")
        cls.addClassCleanup(cls.compiled.cleanup)
        cls.production_check = Path(cls.compiled.name) / "check"
        source = Path(__file__).resolve().parent.parent
        subprocess.run(["go", "build", "-trimpath", "-o", str(cls.production_check), "./check"], cwd=source, check=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="andeiva-offline-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / f"var/lib/andeiva-boot-bundles/{IDENTIFIER}"
        self.bundle.mkdir(parents=True)
        self.bin = self.root / "mock-bin"
        self.bin.mkdir()
        for directory in ["etc/initramfs-tools", "etc/default", "etc/grub.d", "boot/grub", "var/lib/dpkg/updates", "var/backups", "usr/bin", "usr/sbin", "usr/lib", "usr/share/keyrings", "proc/self"]:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        files = {"usr/lib/os-release": 'ID=debian\nVERSION_ID="13"\n', "usr/bin/sqv": "fixture", "usr/share/keyrings/debian-archive-keyring.pgp": "fixture", "etc/initramfs-tools/update-initramfs.conf": "update_initramfs=yes\n", "etc/default/grub": "fixture\n", "boot/grub/grub.cfg": "fixture\n", "var/lib/dpkg/status": "fixture\n", "proc/self/mountinfo": ""}
        for kernel in ["6.12.1-fixture", "6.12.0-fixture"]:
            for prefix in ["vmlinuz-", "initrd.img-"]:
                files["boot/" + prefix + kernel] = "fixture\n"
        profile_source = (Path(__file__).resolve().parent.parent / "check/profile.go").read_text()
        profile = re.search(r"const profileText = `([^`]*)`", profile_source, re.S).group(1)
        status = ""
        for line in profile.splitlines()[1:]:
            kind, name, version, arch, _ = line.split("\t")
            if kind == "baseline":
                status += f"Package: {name}\nStatus: install ok installed\nVersion: {version}\nArchitecture: {arch}\n\n"
        files["var/lib/dpkg/status"] = status
        for name, body in files.items():
            (self.root / name).write_text(body)
        self.mock = self.root / "fixture-dispatch"
        self.mock.write_bytes(Path(__file__).read_bytes())
        self.mock.chmod(0o700)
        for name in ["dpkg", "dpkg-query", "dpkg-deb", "df", "findmnt", "uname", "readlink", "mount", "unshare", "apt-get", "sync"]:
            (self.bin / name).symlink_to(self.mock)
        (self.bundle / "bin").mkdir()
        (self.bundle / "bin/check").write_bytes(self.mock.read_bytes())
        (self.bundle / "archives").mkdir()
        manifest = f"ANDEIVA_BOOT_OFFLINE_V1\t{VERSION}\t1794355200\n"
        for index, (package, arch) in enumerate(PACKAGES, 1):
            name = f"archives/{index:04d}.deb"
            body = b"fixture payload"
            (self.bundle / name).write_bytes(body)
            manifest += f"{name}\tproduct\t{package}\t{VERSION}\t{arch}\t{hashlib.sha256(body).hexdigest()}\n"
        (self.bundle / "manifest.tsv").write_text(manifest)
        source = Path(__file__).resolve().parent.parent
        for name in ["install.sh", "install-in-namespace.sh", "capture.sh"]:
            text = (source / name).read_text()
            text = text.replace("EUID == 0", f"EUID == {os.geteuid()}").replace(") = 0", f") = {os.geteuid()}")
            text = text.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={self.bin}:/usr/sbin:/usr/bin:/sbin:/bin")
            for path in ["/usr/sbin/andeiva-boot-activation", "/usr/lib/os-release", "/usr/share/keyrings", "/usr/bin/sqv", "/proc/self/ns/mnt", "/proc/self/mountinfo", "/sys/firmware/efi", "/var", "/etc", "/boot"]:
                text = re.sub(r"(?<![\w$}])" + re.escape(path), str(self.root) + path, text)
            # Fixture security paths are owned by this test user, not OS root.
            text = text.replace("/usr /usr/bin /usr/share ", f"{self.root}/usr {self.root}/usr/bin {self.root}/usr/share ")
            (self.bundle / name).write_text(text)
        for path in self.root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        self.mock.chmod(0o700)
        (self.root / "usr/bin/sqv").chmod(0o700)
        (self.bundle / "bin/check").chmod(0o700)
        self.env = dict(os.environ, ANDEIVA_FIXTURE_ROOT=str(self.root), ANDEIVA_FIXTURE_CHECK=str(self.production_check), APT_CONFIG="/untrusted/ignored.conf")

    def run_installer(self, operation="install", **env):
        arguments = ["/bin/bash", str(self.bundle / "install.sh"), operation]
        if operation == "install":
            arguments.append("--recovery-verified")
        return subprocess.run(arguments, env=dict(self.env, **env), capture_output=True, text=True, timeout=15)

    def marker(self):
        return self.root / "var/backups/andeiva-boot-offline/install-pending"

    def test_firmware_presence_uses_fixture_not_runner(self):
        script = (self.bundle / "install.sh").read_text()
        firmware = self.root / "sys/firmware/efi"
        self.assertIn(f"! -e {firmware}", script)
        self.assertNotIn("! -e /sys/firmware/efi", script)
        for present in [False, True, False]:
            with self.subTest(efi_present=present):
                if present:
                    firmware.mkdir(parents=True)
                elif firmware.exists():
                    firmware.rmdir()
                result = self.run_installer("inspect")
                if present:
                    self.assertIn("ANDEIVA_OFFLINE_PLATFORM", result.stderr)
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.marker().exists())
                self.assertFalse((self.root / "apt-started").exists())

    def test_inspect_then_install_then_idempotent(self):
        inspect = self.run_installer("inspect")
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        self.assertFalse(self.marker().exists())
        self.assertEqual(list((self.root / "var/backups/andeiva-boot-offline").glob(".inspect.*")), [])
        installed = self.run_installer()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertFalse(self.marker().exists())
        log = (self.root / f"var/backups/andeiva-boot-offline/{IDENTIFIER}/install.log").read_text()
        self.assertIn("APT_STDOUT_FIXTURE", log)
        self.assertIn("APT_STDERR_FIXTURE", log)
        again = self.run_installer()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("ANDEIVA_OFFLINE_ALREADY_INSTALLED", again.stdout)

    def test_standard_keyring_alias_is_not_a_trust_input(self):
        alias = self.root / "usr/share/keyrings/debian-archive-keyring.gpg"
        alias.symlink_to("debian-archive-keyring.pgp")
        result = self.run_installer("inspect")
        self.assertEqual(result.returncode, 0, result.stderr)
        alias.unlink()
        alias.symlink_to("untrusted-other-keyring")
        result = self.run_installer("inspect")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker().exists())

    def test_keyring_symlink_directory_and_writable_file_are_refused(self):
        keyring = self.root / "usr/share/keyrings/debian-archive-keyring.pgp"
        for kind in ["symlink", "directory", "writable", "missing"]:
            with self.subTest(kind=kind):
                keyring.unlink()
                if kind == "symlink":
                    keyring.symlink_to(self.root / "usr/lib/os-release")
                elif kind == "directory":
                    keyring.mkdir(mode=0o700)
                elif kind == "writable":
                    keyring.write_text("fixture")
                    keyring.chmod(0o622)
                result = self.run_installer("inspect")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker().exists())
                self.assertFalse((self.root / "apt-started").exists())
                if keyring.is_dir() and not keyring.is_symlink():
                    keyring.rmdir()
                elif keyring.exists() or keyring.is_symlink():
                    keyring.unlink()
                keyring.write_text("fixture")
                keyring.chmod(0o600)

    def test_keyring_ancestor_symlink_is_refused(self):
        directory = self.root / "usr/share/keyrings"
        moved = self.root / "usr/share/other-keyrings"
        directory.rename(moved)
        directory.symlink_to("other-keyrings", target_is_directory=True)
        result = self.run_installer("inspect")
        self.assertIn("ANDEIVA_OFFLINE_UNSAFE_PATH", result.stderr)
        self.assertFalse(self.marker().exists())
        self.assertFalse((self.root / "apt-started").exists())

    def test_failure_retains_global_marker(self):
        result = self.run_installer(ANDEIVA_FIXTURE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker().exists())
        repeated = self.run_installer()
        self.assertIn("ANDEIVA_OFFLINE_RECOVERY_REQUIRED", repeated.stderr)

    def test_pending_blocks_even_all_packages_installed(self):
        directory = self.marker().parent
        directory.mkdir(parents=True, mode=0o700)
        self.marker().write_text(IDENTIFIER + "\n")
        self.marker().chmod(0o600)
        (self.root / "installed").touch()
        result = self.run_installer()
        self.assertIn("ANDEIVA_OFFLINE_RECOVERY_REQUIRED", result.stderr)
        self.assertFalse((self.root / "apt-started").exists())

    def test_concurrent_installer_rejected(self):
        args = ["/bin/bash", str(self.bundle / "install.sh"), "install", "--recovery-verified"]
        first = subprocess.Popen(args, env=dict(self.env, ANDEIVA_FIXTURE_DELAY="1"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "namespace-started").exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((self.root / "namespace-started").exists())
            second = self.run_installer()
            self.assertIn("ANDEIVA_OFFLINE_BUSY", second.stderr)
            stdout, stderr = first.communicate(timeout=10)
            self.assertEqual(first.returncode, 0, stdout + stderr)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=10)

    def test_parent_death_does_not_clear_pending_marker(self):
        args = ["/bin/bash", str(self.bundle / "install.sh"), "install", "--recovery-verified"]
        parent = subprocess.Popen(args, env=dict(self.env, ANDEIVA_FIXTURE_DELAY=".5"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "apt-started").exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((self.root / "apt-started").exists())
            parent.kill()
            parent.communicate(timeout=10)
            self.assertTrue(self.marker().exists())
            self.assertIn("ANDEIVA_OFFLINE_RECOVERY_REQUIRED", self.run_installer().stderr)
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.communicate(timeout=10)

    def test_old_activator_refused_before_install(self):
        activator = self.root / "usr/sbin/andeiva-boot-activation"
        activator.write_bytes(self.mock.read_bytes())
        activator.chmod(0o700)
        result = self.run_installer(ANDEIVA_FIXTURE_GUARD="0")
        self.assertIn("ANDEIVA_OFFLINE_OLD_ACTIVATOR", result.stderr)
        self.assertFalse(self.marker().exists())
        self.assertFalse((self.root / "apt-started").exists())

    def test_unqualified_layout_refused(self):
        result = self.run_installer(ANDEIVA_FIXTURE_FSTYPE="btrfs")
        self.assertIn("ANDEIVA_OFFLINE_LAYOUT", result.stderr)
        self.assertFalse((self.root / "apt-started").exists())

    def test_missing_baseline_refused_before_idempotent_return(self):
        (self.root / "var/lib/dpkg/status").write_text("")
        (self.root / "installed").touch()
        result = self.run_installer()
        self.assertIn("ANDEIVA_OFFLINE_BASELINE_REQUIRED", result.stderr)
        self.assertFalse(self.marker().exists())
        self.assertFalse((self.root / "apt-started").exists())

    def test_changed_baseline_refused_before_apt(self):
        status = self.root / "var/lib/dpkg/status"
        status.write_text(status.read_text().replace("2.12-9+deb13u2", "2.12-9+deb13u3"))
        result = self.run_installer()
        self.assertIn("ANDEIVA_OFFLINE_BASELINE_REQUIRED", result.stderr)
        self.assertFalse(self.marker().exists())
        self.assertFalse((self.root / "apt-started").exists())

    def test_unhealthy_dpkg_refused(self):
        result = self.run_installer(ANDEIVA_FIXTURE_DPKG_BAD="1")
        self.assertIn("ANDEIVA_OFFLINE_DPKG_UNHEALTHY", result.stderr)
        self.assertFalse((self.root / "apt-started").exists())

    def test_boot_drift_keeps_pending_marker(self):
        result = self.run_installer(ANDEIVA_FIXTURE_BOOT_DRIFT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker().exists())

    def test_shared_mount_namespace_refused(self):
        (self.root / "proc/self/mountinfo").write_text("fixture shared:1\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker().exists())
        self.assertFalse((self.root / "apt-started").exists())

    def test_successful_apt_with_log_overflow_retains_marker(self):
        result = self.run_installer(ANDEIVA_FIXTURE_FLOOD="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "installed").exists())
        self.assertTrue(self.marker().exists())
        log = (self.marker().parent / IDENTIFIER / "install.log").read_bytes()
        self.assertLessEqual(len(log), 4 * 1024 * 1024)
        self.assertTrue(log.endswith(b"\nANDEIVA_OFFLINE_LOG_TRUNCATED\n"))
        self.assertEqual(log.count(b"\nANDEIVA_OFFLINE_LOG_TRUNCATED\n"), 1)

    def test_pipeline_timeout_covers_descendant_holding_stdout(self):
        script = self.bundle / "install.sh"
        text = script.read_text().replace('timeout --kill-after=10s 600s /bin/bash "$bundle/capture.sh" install', 'timeout --kill-after=1s 2s /bin/bash "$bundle/capture.sh" install')
        script.write_text(text)
        started = time.monotonic()
        result = self.run_installer(ANDEIVA_FIXTURE_HOLD_PIPE="1")
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker().exists())


if __name__ == "__main__":
    if Path(sys.argv[0]).name != "installer_fixture.py":
        mock_command()
    else:
        unittest.main()
