#!/usr/bin/env python3
"""Inspect a data package without installing or extracting it."""
import hashlib
import io
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import subprocess
import sys
import tarfile
import time

APPROVED_LOGO = "1f79f5ec7f33327c9285c702b63fc5c5a618a28395b2161d594001fdb0199f81"
MAX_TAR_BYTES = 3 * 1024 * 1024
MAX_TAR_SECONDS = 10
GRUB = "usr/share/grub/themes/andeiva/"
PLYMOUTH = "usr/share/plymouth/themes/andeiva/"
DOC = "usr/share/doc/andeiva-boot-branding/"
EXPECTED = {
    GRUB + name for name in ("andeiva-logo.png", "background.png", "theme.txt")
} | {
    PLYMOUTH + name for name in ("andeiva-logo.png", "background.png", "activity-track.png",
                                "activity-segment.png", "andeiva.plymouth", "andeiva.script")
} | {
    DOC + name for name in ("LICENSE", "NOTICE", "README.md", "DESIGN.md", "docs/en.md",
                            "docs/es.md", "docs/pt.md")
}
DIRECTORIES = {"", "."} | {
    str(parent) for name in EXPECTED for parent in PurePosixPath(name).parents
}


def reject(code):
    raise ValueError(code)


def read_tar(package, flag):
    # Bound decompressed bytes before materializing an archive or its members.
    # A separate process group also contains dpkg's decompressor on rejection.
    with subprocess.Popen(["dpkg-deb", flag, package], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as process:
        deadline = time.monotonic() + MAX_TAR_SECONDS
        data = bytearray()
        completed = False
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        reject("ANDEIVA_BOOT_ARCHIVE_TIMEOUT")
                    chunk = os.read(process.stdout.fileno(), min(65536, MAX_TAR_BYTES + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > MAX_TAR_BYTES:
                        reject("ANDEIVA_BOOT_ARCHIVE_SIZE")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reject("ANDEIVA_BOOT_ARCHIVE_TIMEOUT")
            if process.wait(timeout=remaining):
                reject("ANDEIVA_BOOT_ARCHIVE_COMMAND")
            completed = True
            return bytes(data)
        finally:
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)


def archive(package, flag):
    # dpkg reads the explicitly supplied development artifact; no shell or install.
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(read_tar(package, flag)), mode="r|") as tar:
        for count, item in enumerate(tar, 1):
            total += item.size
            if count > 80 or total > 2 * 1024 * 1024:
                reject("ANDEIVA_BOOT_PACKAGE_BUDGET")
            name = item.name.removeprefix("./").rstrip("/")
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or item.issym() or item.islnk():
                reject("ANDEIVA_BOOT_PACKAGE_PATH")
            if not (item.isfile() or item.isdir()) or item.uid or item.gid:
                reject("ANDEIVA_BOOT_PACKAGE_METADATA")
            if item.isfile():
                if flag == "--ctrl-tarfile" and name not in {"control", "md5sums"}:
                    reject("ANDEIVA_BOOT_PACKAGE_ACTIVE_CONTENT")
                if name in files or item.mode != 0o644:
                    reject("ANDEIVA_BOOT_PACKAGE_MODE")
                files[name] = tar.extractfile(item).read()
            else:
                if item.mode != 0o755:
                    reject("ANDEIVA_BOOT_PACKAGE_MODE")
                if flag == "--fsys-tarfile" and name not in DIRECTORIES:
                    reject("ANDEIVA_BOOT_PACKAGE_PATH")
    return files


def check_control(data):
    fields = {}
    current = None
    for line in data.decode("utf-8").splitlines():
        if line.startswith(" ") and current == "description":
            fields[current] += "\n" + line
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z-]*): (.+)", line)
        if not match:
            reject("ANDEIVA_BOOT_PACKAGE_CONTROL")
        current = match[1].lower()
        if current in fields:
            reject("ANDEIVA_BOOT_PACKAGE_CONTROL")
        fields[current] = match[2]
    required = {
        "package": "andeiva-boot-branding", "architecture": "all", "maintainer": "ASTERG",
        "section": "admin", "priority": "optional",
    }
    if set(fields) != set(required) | {"version", "description"}:
        reject("ANDEIVA_BOOT_PACKAGE_CONTROL")
    if any(fields[key] != value for key, value in required.items()):
        reject("ANDEIVA_BOOT_PACKAGE_CONTROL")
    if not re.fullmatch(r"0\.1\.0~alpha[1-9][0-9]{0,5}", fields["version"]):
        reject("ANDEIVA_BOOT_PACKAGE_CONTROL")
    if not fields["description"].startswith("Experimental ANDEIVA boot theme resources\n"):
        reject("ANDEIVA_BOOT_PACKAGE_CONTROL")


def check(package):
    control = archive(package, "--ctrl-tarfile")
    if set(control) != {"control", "md5sums"}:
        reject("ANDEIVA_BOOT_PACKAGE_ACTIVE_CONTENT")
    check_control(control["control"])
    payload = archive(package, "--fsys-tarfile")
    if set(payload) != EXPECTED:
        reject("ANDEIVA_BOOT_PACKAGE_CONTENTS")
    for prefix in (GRUB, PLYMOUTH):
        logo = payload[prefix + "andeiva-logo.png"]
        if hashlib.sha256(logo).hexdigest() != APPROVED_LOGO:
            reject("ANDEIVA_BOOT_LOGO_INTEGRITY")
        if logo[:8] != b"\x89PNG\r\n\x1a\n" or logo[16:24] != (1100).to_bytes(4, "big") + (550).to_bytes(4, "big"):
            reject("ANDEIVA_BOOT_LOGO_DIMENSIONS")
    script = payload[PLYMOUTH + "andeiva.script"].decode()
    theme = payload[GRUB + "theme.txt"].decode()
    for forbidden in ("SetBootProgressFunction", "Image.Crop", "Image.Rotate", "GetEnvironment", "GetCommandLine", "%"):
        if forbidden in script:
            reject("ANDEIVA_BOOT_SPLASH_CONTRACT")
    expected_text = {
        "ANDEIVA OS", "Network Security Appliance", "Press Esc for diagnostics",
        "System activity...", "Starting system...", "Restarting...", "Shutting down...",
        "Updating system...",
    }
    actual_text = set(re.findall(r'Image.Text\("([^"\n]*)"', script))
    actual_text |= set(re.findall(r'status.text = "([^"\n]*)"', script))
    if actual_text != expected_text:
        reject("ANDEIVA_BOOT_SPLASH_LANGUAGE")
    for callback in ("SetDisplayNormalFunction", "SetDisplayPasswordFunction", "SetDisplayQuestionFunction",
                     "SetDisplayMessageFunction", "SetHideMessageFunction", "SetRefreshFunction"):
        if callback not in script:
            reject("ANDEIVA_BOOT_SPLASH_CALLBACK")
    if "width = 320\n  height = 160" not in theme or "andeiva-logo.png" not in theme:
        reject("ANDEIVA_BOOT_GRUB_LOGO_RATIO")
    inventory = set()
    for line in control["md5sums"].decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  (.+)", line)
        if not match:
            reject("ANDEIVA_BOOT_PACKAGE_CHECKSUM")
        digest, path = match.groups()
        if path in inventory:
            reject("ANDEIVA_BOOT_PACKAGE_CHECKSUM")
        inventory.add(path)
        if path not in payload or hashlib.md5(payload[path]).hexdigest() != digest:
            reject("ANDEIVA_BOOT_PACKAGE_CHECKSUM")
    if inventory != set(payload):
        reject("ANDEIVA_BOOT_PACKAGE_CHECKSUM")
    print("ANDEIVA_BOOT_STATIC_PACKAGE_OK")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            reject("Usage: check-package.py PACKAGE.deb")
        check(sys.argv[1])
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
