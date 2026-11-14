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


if __name__ == '__main__':
    unittest.main()
