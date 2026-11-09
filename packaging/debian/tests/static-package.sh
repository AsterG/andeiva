#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077

if [[ $# != 4 || $1 != --package || $3 != --evidence-dir ]]; then
  printf 'Usage: bash static-package.sh --package FILE.deb --evidence-dir NEW_DIRECTORY\n' >&2
  exit 2
fi
for command in python3 dpkg-deb realpath; do
  command -v "$command" >/dev/null || { printf 'Missing test prerequisite: %s\n' "$command" >&2; exit 2; }
done
package=$(realpath -e -- "$2")
evidence=$(realpath -m -- "$4")
source_root=$(realpath -e -- "$(dirname -- "${BASH_SOURCE[0]}")/../../..")
case "$evidence/" in "$source_root/"*) printf 'Evidence must be outside the source tree.\n' >&2; exit 2;; esac
[[ -f $package && ! -e $evidence && ! -L $evidence ]] || { printf 'Package must exist and evidence directory must be new.\n' >&2; exit 2; }
mkdir -m 700 -- "$evidence"

# Python is a host/CI test prerequisite only; the package and VM lifecycle do not need it.
python3 - "$package" "$evidence" <<'PY'
import configparser
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile

package, evidence = map(pathlib.Path, sys.argv[1:])
assert package.stat().st_size <= 100 * 1024 * 1024, 'Unexpected package size'
package_hash = hashlib.sha256(package.read_bytes()).hexdigest()
fields = {}
for key in ('Package', 'Version', 'Architecture', 'Maintainer', 'Description'):
    fields[key] = subprocess.check_output(['dpkg-deb', '--field', str(package), key], text=True).strip()
assert fields['Package'] == 'andeiva-experimental', fields
assert re.fullmatch(r'0\.0\.0~exp[1-9][0-9]*', fields['Version']), fields
assert fields['Architecture'] == 'amd64', fields

data_files = {
    'usr/bin/andeiva': 0o755,
    'usr/lib/andeiva/andeiva-api': 0o755,
    'usr/lib/andeiva/wait-ready': 0o755,
    'usr/lib/systemd/system/andeiva-api.service': 0o644,
    'etc/andeiva/andeiva-api.env': 0o644,
    **{f'usr/share/doc/andeiva-experimental/{name}': 0o644
       for name in ('copyright', 'LICENSE', 'NOTICE', 'LICENSE.Go', 'build-info.txt')},
}
control_files = {'control': 0o644, 'conffiles': 0o644, 'md5sums': 0o644,
                 'preinst': 0o755, 'postinst': 0o755, 'prerm': 0o755, 'postrm': 0o755}
inventory = []
payload = {}

def inspect_archive(option, allowlist, category):
    allowed_dirs = {'.'}
    for name in allowlist:
        allowed_dirs.update(str(parent) for parent in pathlib.PurePosixPath(name).parents)
    seen = set()
    total = 0
    # Read tar metadata before writing any member; symlinks, devices and traversal are rejected.
    process = subprocess.Popen(['dpkg-deb', option, str(package)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/') or '.'
                assert not name.startswith('/') and '..' not in pathlib.PurePosixPath(name).parts, name
                assert name not in seen, f'Duplicate member: {name}'
                seen.add(name)
                assert member.uid == 0 and member.gid == 0, f'Non-root archive owner: {name}'
                if member.isdir():
                    assert name in allowed_dirs and member.mode == 0o755, f'Unexpected directory/mode: {name}'
                    continue
                assert member.isfile() and name in allowlist, f'Unexpected member/type: {name}'
                assert member.mode == allowlist[name], f'Unexpected file mode: {name}: {member.mode:o}'
                total += member.size
                assert total <= 256 * 1024 * 1024 and member.size <= 64 * 1024 * 1024
                contents = archive.extractfile(member).read()
                assert len(contents) == member.size
                payload[(category, name)] = contents
                inventory.append({'archive': category, 'path': name, 'bytes': member.size,
                                  'mode': f'{member.mode:04o}', 'sha256': hashlib.sha256(contents).hexdigest()})
        assert process.wait() == 0, f'dpkg-deb failed: {option}'
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert set(allowlist).issubset(seen), f'Missing {category} members: {set(allowlist) - seen}'

inspect_archive('--ctrl-tarfile', control_files, 'control')
inspect_archive('--fsys-tarfile', data_files, 'data')
checksums = {}
for line in payload['control', 'md5sums'].decode().splitlines():
    match = re.fullmatch(r'([0-9a-f]{32})  (.+)', line)
    assert match, 'Invalid md5sums entry'
    digest, name = match.groups()
    assert name in data_files and name not in checksums, 'Unknown or duplicate md5sums path'
    assert hashlib.md5(payload['data', name], usedforsecurity=False).hexdigest() == digest, name
    checksums[name] = digest
assert checksums.keys() == data_files.keys(), 'Incomplete md5sums inventory'
assert payload['control', 'conffiles'].decode().splitlines() == ['/etc/andeiva/andeiva-api.env']
env = payload['data', 'etc/andeiva/andeiva-api.env'].decode()
assert [line for line in env.splitlines() if line.strip() and not line.startswith('#')] == ['ANDEIVA_LISTEN_ADDR=127.0.0.1:4000']
assert b'Apache License' in payload['data', 'usr/share/doc/andeiva-experimental/LICENSE']
assert b'Copyright 2009 The Go Authors.' in payload['data', 'usr/share/doc/andeiva-experimental/LICENSE.Go']
assert b'ANDEIVA' in payload['data', 'usr/share/doc/andeiva-experimental/NOTICE']
for name in ('usr/bin/andeiva', 'usr/lib/andeiva/andeiva-api'):
    binary = payload['data', name]
    assert binary[:4] == b'\x7fELF' and binary[4:6] == b'\x02\x01', f'Not ELF64 little endian: {name}'
    assert int.from_bytes(binary[18:20], 'little') == 62, f'Not x86-64: {name}'

unit_text = payload['data', 'usr/lib/systemd/system/andeiva-api.service'].decode()
unit = configparser.ConfigParser(interpolation=None, strict=True)
unit.optionxform = str
unit.read_string(unit_text)
required = {
    'ExecStart': '/usr/lib/andeiva/andeiva-api',
    'ExecStartPost': '/usr/lib/andeiva/wait-ready',
    'EnvironmentFile': '/etc/andeiva/andeiva-api.env',
    'DynamicUser': 'yes', 'User': 'andeiva-api', 'RuntimeDirectory': 'andeiva-api',
    'RuntimeDirectoryMode': '0750', 'NoNewPrivileges': 'yes',
    'ProtectSystem': 'strict', 'ProtectHome': 'yes',
    'PrivateTmp': 'yes', 'PrivateDevices': 'yes',
    'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
}
for key, expected in required.items():
    assert unit['Service'].get(key) == expected, f'Unexpected service property {key}'
for section in unit.sections():
    for key, value in unit[section].items():
        assert not (key.startswith('Exec') and key not in ('ExecStart', 'ExecStartPost')), key
        assert key not in ('StateDirectory', 'CacheDirectory', 'LogsDirectory', 'RootDirectory'), key
assert unit['Service'].get('RestrictAddressFamilies', '').split() == ['AF_UNIX', 'AF_INET', 'AF_INET6']
assert unit['Install'].get('WantedBy') == 'multi-user.target'

# Syntax checks do not run maintainer scripts or start the application.
for category, name in [('control', x) for x in ('preinst', 'postinst', 'prerm', 'postrm')] + [('data', 'usr/lib/andeiva/wait-ready')]:
    subprocess.run(['/bin/sh', '-n'], input=payload[category, name], check=True)

verify = {'status': 'NOT_RUN', 'reason': 'systemd-analyze unavailable; installed verification remains a VM gate'}
analyze = shutil.which('systemd-analyze')
if analyze:
    staged = evidence / 'verify-stage'
    staged.mkdir(mode=0o700)
    for name in ('andeiva-api', 'wait-ready'):
        path = staged / name
        path.write_bytes(payload['data', 'usr/lib/andeiva/' + name])
        path.chmod(0o755)
    # Translate only executable paths for static verification on an uninstalled host.
    # Installed paths, sandbox enforcement and boot behavior still require the VM suite.
    def unit_quote(path):
        return '"' + str(path).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
    translated = unit_text.replace('ExecStart=/usr/lib/andeiva/andeiva-api', 'ExecStart=' + unit_quote(staged / 'andeiva-api'))
    translated = translated.replace('ExecStartPost=/usr/lib/andeiva/wait-ready', 'ExecStartPost=' + unit_quote(staged / 'wait-ready'))
    unit_path = staged / 'andeiva-api.service'
    unit_path.write_text(translated)
    result = subprocess.run([analyze, 'verify', '--man=no', str(unit_path)], text=True, capture_output=True)
    (evidence / 'systemd-verify.txt').write_text(result.stdout + result.stderr)
    verify = {'status': 'PASS' if result.returncode == 0 else 'FAIL', 'exit_code': result.returncode,
              'scope': 'Static unit verification with staged executable paths; no service was started',
              'host_systemd_version': subprocess.check_output([analyze, '--version'], text=True).splitlines()[0],
              'warnings_present': bool(result.stderr.strip()),
              'compatibility': 'Host version only; Debian 13 effective enforcement remains a VM gate'}
    assert result.returncode == 0, 'systemd-analyze verify failed; inspect evidence'

report = {'status': 'PASS', 'package_sha256': package_hash, 'control': fields, 'members': inventory,
          'systemd_verify': verify,
          'limits': 'No package installation, VM lifecycle, signature authenticity, full secret scan or complete license clearance was performed.'}
(evidence / 'static-report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': 'PASS', 'package': fields['Package'], 'version': fields['Version'], 'sha256': package_hash}))
PY
