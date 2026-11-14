#!/usr/bin/env python3
"""Nonroot development bundler. No package installation or maintainer execution."""
import csv
import datetime
import email.utils
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
PROFILE = HERE / 'check/profile'
KEY_SHA = '506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017'
BASE_SHA = 'fcd42bb5cb63f7bfc4326a92541247872206d60a192fdff65ca14eb83ed408b9'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def manifest_paths(root):
    # The verifier compares serialized POSIX names, not pathlib components.
    return sorted((path for path in root.rglob('*') if path.is_file()),
                  key=lambda path: path.relative_to(root).as_posix())


def checked(path, expected, size=None):
    assert path.is_file() and not path.is_symlink(), str(path)
    assert path.stat().st_size <= 256 * 1024 * 1024
    assert digest(path) == expected, str(path)
    if size is not None:
        assert path.stat().st_size == int(size), str(path)
    return path


def paragraphs(text):
    result, key = {}, None
    for line in text.splitlines() + ['']:
        if not line:
            if result:
                yield result
            result, key = {}, None
        elif line[0].isspace() and key:
            result[key] += '\n' + line.strip()
        elif ':' in line and not line.startswith('-'):
            key, value = line.split(':', 1)
            assert key not in result
            result[key] = value.strip()


def authenticate(release, keyring):
    subprocess.run(['/usr/bin/gpgv', '--keyring', str(keyring), str(release)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    fields = next(p for p in paragraphs(release.read_text()) if 'SHA256' in p)
    now = datetime.datetime.now(datetime.timezone.utc)
    date = email.utils.parsedate_to_datetime(fields['Date'])
    assert date <= now + datetime.timedelta(minutes=5)
    if fields['Codename'] != 'trixie':
        assert date <= now <= email.utils.parsedate_to_datetime(fields['Valid-Until'])
    sums = {}
    for line in fields['SHA256'].splitlines():
        if line.strip():
            sha, size, name = line.split()
            assert name not in sums
            sums[name] = sha, int(size)
    return sums


def member(path, wanted):
    # Stream an authenticated archive; never materialize an archive tree.
    proc = subprocess.Popen(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    found = {}
    try:
        with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
            for entry in tar:
                name = entry.name.removeprefix('./')
                assert not name.startswith('/') and '..' not in PurePosixPath(name).parts
                if name not in wanted:
                    continue
                assert name not in found and entry.isfile() and entry.size <= 2 * 1024 * 1024
                found[name] = tar.extractfile(entry).read()
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
    assert set(found) == set(wanted)
    return found


def main():
    assert os.geteuid() != 0 and len(sys.argv) == 6, (
        'nonroot DEV: build.py DEB_CACHE SOURCE_CACHE BINARY_LISTS BASE_FILES_REFERENCE.deb NEW_OUTPUT')
    debs, sources, binary_lists, base_ref, out = map(lambda p: Path(p).resolve(), sys.argv[1:])
    assert not out.exists()
    assert subprocess.check_output(['go', 'env', 'GOVERSION'], text=True,
                                   env=dict(os.environ, GOTOOLCHAIN='local')).strip() == 'go1.27.4'
    keyring = checked(sources / 'keys/debian-archive-keyring.gpg', KEY_SHA)
    provenance = json.loads((PROFILE / 'provenance.json').read_text())
    authenticated = {}
    for row in provenance:
        folder = binary_lists if row['source'] == 'binary' else sources / 'state/lists'
        path = checked(folder / row['filename'], row['sha256'], row['bytes'])
        if path.name.endswith('_InRelease'):
            authenticated[row['source'], path.name.removesuffix('_InRelease')] = authenticate(path, keyring)
    records = []
    for row in provenance:
        if row['filename'].endswith('_InRelease'):
            continue
        folder = binary_lists if row['source'] == 'binary' else sources / 'state/lists'
        path = folder / row['filename']
        suffix = '_main_binary-amd64_Packages' if row['source'] == 'binary' else '_main_source_Sources'
        key = 'main/binary-amd64/Packages' if row['source'] == 'binary' else 'main/source/Sources'
        assert authenticated[row['source'], path.name.removesuffix(suffix)][key] == (row['sha256'], row['bytes'])
        records.extend((row['source'], r) for r in paragraphs(path.read_text()))
    inventory = json.loads((PROFILE / 'supply-chain.json').read_text())
    packages = inventory['packages']
    paths = {}
    needed = {r['deb_sha256'] for r in packages} | {r['copyright_origin_deb_sha256'] for r in packages}
    for path in debs.glob('*.deb'):
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 32 * 1024 * 1024
        sha = digest(path)
        if sha in needed:
            assert sha not in paths
            paths[sha] = path
    assert set(paths) == needed
    for p in packages:
        assert any(kind == 'binary' and r.get('Package') == p['package'] and
                   r.get('Version') == p['version'] and r.get('Architecture') == p['architecture'] and
                   r.get('SHA256') == p['deb_sha256'] for kind, r in records), p['package']
    source_map = json.loads((PROFILE / 'source-map.json').read_text())
    for p in source_map:
        candidates = [r for kind, r in records if kind == 'source' and
                      r.get('Package') == p['source_package'] and r.get('Version') == p['source_version']]
        assert candidates
        for f in p['files']:
            checked(sources / f['path'], f['sha256'], f['bytes'])
            assert any(f"{f['sha256']} {f['bytes']} {Path(f['path']).name}" in r['Checksums-Sha256'] for r in candidates)
    checked(base_ref, BASE_SHA, 88296)
    assert any(kind == 'binary' and r.get('Package') == 'base-files' and r.get('SHA256') == BASE_SHA for kind, r in records)
    out.mkdir(mode=0o755)
    for directory in ('archives', 'bin', 'docs', 'licenses', 'sources', 'provenance/binary', 'provenance/source'):
        (out / directory).mkdir(parents=True, exist_ok=True)
    for p in packages:
        data = member(paths[p['copyright_origin_deb_sha256']], [p['copyright_member']])[p['copyright_member']]
        assert hashlib.sha256(data).hexdigest() == p['copyright_sha256']
        (out / 'licenses' / (p['package'] + '.copyright')).write_bytes(data)
        if p['scope'] == 'new-package':
            leaf = p['package'] + '_' + p['version'].replace(':', '%3a') + '_' + p['architecture'] + '.deb'
            shutil.copyfile(paths[p['deb_sha256']], out / 'archives' / leaf)
    common = ['Apache-2.0', 'Artistic', 'BSD', 'CC0-1.0', 'GFDL-1.2', 'GFDL-1.3', 'GPL-1', 'GPL-2', 'GPL-3', 'LGPL-2', 'LGPL-2.1', 'LGPL-3', 'MPL-1.1', 'MPL-2.0']
    texts = member(base_ref, ['usr/share/common-licenses/' + name for name in common])
    (out / 'licenses/common').mkdir()
    for path, data in texts.items():
        (out / 'licenses/common' / Path(path).name).write_bytes(data)
    (out / 'licenses/common/PROVENANCE.txt').write_text('Debian base-files 13.8+deb13u7 amd64\nSHA256 ' + BASE_SHA + '\nReference payload only; NOT an installation dependency. Original common-license text names preserved.\n')
    for p in source_map:
        for f in p['files']:
            target = out / 'sources' / f['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sources / f['path'], target)
    for row in provenance:
        folder = binary_lists if row['source'] == 'binary' else sources / 'state/lists'
        shutil.copyfile(folder / row['filename'], out / 'provenance' / row['source'] / row['filename'])
    for name in ('supply-chain.json', 'source-map.json', 'provenance.json', 'archives.tsv', 'baseline.tsv', 'maintainer-scripts.json'):
        shutil.copyfile(PROFILE / name, out / name)
    for path in (HERE / 'docs').glob('*.md'):
        shutil.copyfile(path, out / 'docs' / path.name)
    repo = HERE.parents[2]
    for name in ('LICENSE', 'NOTICE'):
        shutil.copyfile(repo / name, out / name)
    env = os.environ.copy()
    env.update(GOENV='off', GOTOOLCHAIN='local', GOWORK='off', GOTELEMETRY='off', GOPROXY='off', GOSUMDB='off',
               GOFLAGS='', GOEXPERIMENT='', CGO_ENABLED='0', GOOS='linux', GOARCH='amd64', GOAMD64='v1')
    subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o', str(out / 'bin/check'),
                    './packaging/dhcp-server/offline/check'], cwd=repo, env=env, check=True, timeout=120)
    goroot = subprocess.check_output(['go', 'env', 'GOROOT'], env=env, text=True).strip()
    shutil.copyfile(Path(goroot) / 'LICENSE', out / 'licenses/GO-LICENSE')
    shutil.copyfile(repo / 'vendor/golang.org/x/sys/LICENSE' if (repo / 'vendor/golang.org/x/sys/LICENSE').exists()
                    else Path(subprocess.check_output(['go', 'env', 'GOMODCACHE'], env=env, text=True).strip()) / 'golang.org/x/sys@v0.49.0/LICENSE',
                    out / 'licenses/X-SYS-LICENSE')
    entries = []
    for path in manifest_paths(out):
        if path.is_file():
            path.chmod(0o755 if path == out / 'bin/check' else 0o644)
            entries.append(digest(path) + '  ' + path.relative_to(out).as_posix() + '\n')
    raw = ''.join(entries).encode()
    (out / 'SHA256SUMS').write_bytes(raw)
    print(json.dumps({'bundle_id': hashlib.sha256(raw).hexdigest(), 'files': len(entries) + 1,
                      'note': 'Development artifact; not signed ANDEIVA release or installation qualification'}))


if __name__ == '__main__':
    main()
