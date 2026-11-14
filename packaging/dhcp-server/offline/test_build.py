import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BoundaryTests(unittest.TestCase):
    def test_hash_size_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'
            path.write_bytes(b'known archive')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(builder.checked(path, digest, 13), path)
            for sha, size in [('0' * 64, 13), (digest, 12)]:
                with self.assertRaises(AssertionError):
                    builder.checked(path, sha, size)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(AssertionError):
                builder.checked(alias, digest)

    def test_duplicate_field(self):
        with self.assertRaises(AssertionError):
            list(builder.paragraphs('Package: a\nPackage: b\n'))

    def test_multiline_checksums(self):
        result = list(builder.paragraphs('Package: a\nChecksums-Sha256:\n aaa 12 a.tar\n'))
        self.assertEqual(result[0]['Checksums-Sha256'], '\naaa 12 a.tar')


class ManifestOrderTests(unittest.TestCase):
    def test_shared_file_and_directory_prefix_uses_wire_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'provenance/binary').mkdir(parents=True)
            (root / 'provenance/binary/InRelease').write_text('signed metadata')
            (root / 'provenance.json').write_text('{}')
            (root / 'NOTICE').write_text('notice')
            names = [path.relative_to(root).as_posix() for path in builder.manifest_paths(root)]
            self.assertEqual(names, ['NOTICE', 'provenance.json', 'provenance/binary/InRelease'])

    def test_empty_directories_are_not_manifest_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'empty').mkdir()
            self.assertEqual(builder.manifest_paths(root), [])



if __name__ == '__main__':
    unittest.main()
