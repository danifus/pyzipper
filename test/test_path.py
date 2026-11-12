import io
import os
import pathlib
import pickle
import shutil
import stat
import tempfile
import unittest

import pyzipper
from pyzipper import _path

PWD = b'lost art of keeping a secret'


class PlainZipFileMixin:
    """Unencrypted archive handled by pyzipper.ZipFile."""

    zipfile_cls = pyzipper.ZipFile
    encryption = None
    pwd = None


class PlainAESZipFileMixin:
    """Unencrypted archive handled by pyzipper.AESZipFile."""

    zipfile_cls = pyzipper.AESZipFile
    encryption = None
    pwd = None


class EncryptedMixin:
    """WinZip AES encrypted archive."""

    zipfile_cls = pyzipper.AESZipFile
    encryption = pyzipper.WZ_AES
    pwd = PWD


class PathTestsBase:
    """
    Archive layout::

        .
        ├── a.txt
        ├── b
        │   ├── c.txt
        │   ├── d
        │   │   └── e.txt
        │   └── f.txt
        └── g
            └── h
                └── i.txt

    Directory entries are implied only (not stored in the archive).
    """

    files = {
        'a.txt': b'content of a',
        'b/c.txt': b'content of c',
        'b/d/e.txt': b'content of e',
        'b/f.txt': b'content of f',
        'g/h/i.txt': b'content of i',
    }

    def setUp(self):
        self.data = io.BytesIO()
        with self.open_zip('w') as zf:
            for name, content in self.files.items():
                zf.writestr(name, content)

    def open_zip(self, mode='r', file=None, set_pwd=True):
        kwargs = {}
        if self.encryption is not None:
            kwargs['encryption'] = self.encryption
        zf = self.zipfile_cls(self.data if file is None else file, mode, **kwargs)
        if set_pwd and self.pwd:
            zf.setpassword(self.pwd)
        zf.filename = zf.filename or 'mem/abcde.zip'
        return zf

    def root(self):
        zf = self.open_zip()
        self.addCleanup(zf.close)
        return pyzipper.Path(zf)

    def test_members_are_encrypted(self):
        with self.open_zip() as zf:
            for info in zf.infolist():
                self.assertEqual(bool(info.flag_bits & 0x1), self.encryption is not None)

    def test_root_keeps_zipfile_class(self):
        zf = self.open_zip()
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf)
        self.assertIs(root.root, zf)
        self.assertIsInstance(zf, self.zipfile_cls)
        self.assertIsInstance(zf, _path._FastLookupMixin)
        # the plain ZipFile must not silently become an AESZipFile
        self.assertEqual(isinstance(zf, pyzipper.AESZipFile),
                         issubclass(self.zipfile_cls, pyzipper.AESZipFile))
        # a second Path on the same object reuses it unchanged
        cls = type(zf)
        pyzipper.Path(zf)
        self.assertIs(type(zf), cls)

    def test_iterdir_and_types(self):
        root = self.root()
        self.assertTrue(root.is_dir())
        a, b, g = sorted(root.iterdir(), key=lambda p: p.name)
        self.assertEqual([a.name, b.name, g.name], ['a.txt', 'b', 'g'])
        self.assertTrue(a.is_file())
        self.assertFalse(a.is_dir())
        self.assertTrue(b.is_dir())
        self.assertFalse(b.is_file())
        self.assertEqual(sorted(p.name for p in b.iterdir()), ['c.txt', 'd', 'f.txt'])
        (h,) = g.iterdir()
        self.assertTrue(h.is_dir())
        with self.assertRaises(ValueError):
            list(a.iterdir())

    def test_read(self):
        root = self.root()
        for name, content in self.files.items():
            with self.subTest(name=name):
                path = root.joinpath(name)
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(path.read_text(encoding='utf-8'), content.decode())

    def test_open(self):
        root = self.root()
        with (root / 'a.txt').open(encoding='utf-8') as strm:
            self.assertEqual(strm.read(), 'content of a')
        with (root / 'b' / 'c.txt').open('rb') as strm:
            self.assertEqual(strm.read(), b'content of c')
        with self.assertRaises(ValueError):
            (root / 'a.txt').open('rb', 'utf-8')
        with self.assertRaises(IsADirectoryError):
            (root / 'b').open()
        with self.assertRaises(FileNotFoundError):
            (root / 'missing.txt').open()

    def test_joinpath_and_parent(self):
        root = self.root()
        e = root / 'b' / 'd' / 'e.txt'
        self.assertEqual(e.at, 'b/d/e.txt')
        self.assertEqual(root.joinpath('b', 'd', 'e.txt'), e)
        self.assertEqual(root.joinpath('b/d/e.txt'), e)
        self.assertEqual((root / 'b').at, 'b/')
        self.assertEqual(e.parent.at, 'b/d/')
        self.assertEqual(e.parent.parent.at, 'b/')
        self.assertEqual(e.parent.parent.parent.at, '')
        self.assertEqual(root.parent, pathlib.Path('mem'))

    def test_exists(self):
        root = self.root()
        # like zipfile.Path, the root itself is not an archive member
        self.assertFalse(root.exists())
        self.assertTrue((root / 'b').exists())
        self.assertTrue((root / 'b/d/e.txt').exists())
        self.assertFalse((root / 'missing.txt').exists())
        self.assertFalse((root / 'missing.txt').is_file())

    def test_names(self):
        root = self.root()
        self.assertEqual(root.name, 'abcde.zip')
        self.assertEqual(root.filename, pathlib.Path('mem/abcde.zip'))
        e = root / 'b/d/e.txt'
        self.assertEqual((e.name, e.stem, e.suffix, e.suffixes), ('e.txt', 'e', '.txt', ['.txt']))
        self.assertEqual(str(e), 'mem/abcde.zip/b/d/e.txt')
        self.assertEqual(repr(e), "Path('mem/abcde.zip', 'b/d/e.txt')")
        self.assertEqual(e.relative_to(root), 'b/d/e.txt')
        self.assertEqual(e.relative_to(root, 'b'), 'd/e.txt')

    def test_glob(self):
        root = self.root()

        def ats(paths):
            return sorted(p.at for p in paths)

        self.assertEqual(ats(root.glob('*.txt')), ['a.txt'])
        self.assertEqual(ats(root.glob('b/*.txt')), ['b/c.txt', 'b/f.txt'])
        self.assertEqual(ats(root.glob('**/*.txt')), ['b/c.txt', 'b/d/e.txt', 'b/f.txt', 'g/h/i.txt'])
        self.assertEqual(ats(root.rglob('e.txt')), ['b/d/e.txt'])
        self.assertEqual(ats((root / 'b').glob('*')), ['b/c.txt', 'b/d/', 'b/f.txt'])
        self.assertEqual(ats(root.glob('?.txt')), ['a.txt'])
        self.assertTrue((root / 'b/d/e.txt').match('*.txt'))
        with self.assertRaises(ValueError):
            root.glob('')
        with self.assertRaises(ValueError):
            root.glob('**foo')

    def test_eq_hash(self):
        root = self.root()
        self.assertEqual(root / 'a.txt', root / 'a.txt')
        self.assertNotEqual(root / 'a.txt', root / 'b')
        self.assertNotEqual(root, 'mem/abcde.zip')
        self.assertEqual(hash(root / 'a.txt'), hash(root / 'a.txt'))

    def test_is_symlink(self):
        root = self.root()
        self.assertFalse((root / 'a.txt').is_symlink())
        self.assertFalse((root / 'b').is_symlink())

        with self.open_zip('a') as zf:
            info = zf.zipinfo_cls('link')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, 'a.txt')
        self.assertTrue((self.root() / 'link').is_symlink())

    def test_explicit_dir_entries(self):
        with self.open_zip('a') as zf:
            zf.writestr('b/', b'')
            zf.writestr('j/', b'')
        root = self.root()
        self.assertEqual(sorted(p.name for p in root.iterdir()), ['a.txt', 'b', 'g', 'j'])
        self.assertTrue((root / 'j').is_dir())
        self.assertEqual(list((root / 'j').iterdir()), [])

    def test_writable_zipfile(self):
        """A Path on a zipfile open for writing sees members as they are added."""
        data = io.BytesIO()
        with self.open_zip('w', file=data) as zf:
            root = pyzipper.Path(zf)
            self.assertIsInstance(zf, self.zipfile_cls)
            self.assertNotIsInstance(zf, _path._FastLookupMixin)
            self.assertEqual(list(root.iterdir()), [])
            zf.writestr('x/y.txt', b'content of y')
            self.assertEqual([p.name for p in root.iterdir()], ['x'])
            with (root / 'x' / 'z.txt').open('w', encoding='utf-8') as strm:
                strm.write('content of z')
        with self.open_zip(file=data) as zf:
            self.assertEqual(zf.read('x/y.txt'), b'content of y')
            self.assertEqual(zf.read('x/z.txt'), b'content of z')
            for info in zf.infolist():
                self.assertEqual(bool(info.flag_bits & 0x1), self.encryption is not None)

    def test_from_filename(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        for filename in (os.path.join(tmpdir, 'abcde.zip'), pathlib.Path(tmpdir) / 'pathlike.zip'):
            with self.subTest(type=type(filename).__name__):
                with open(filename, 'wb') as f:
                    f.write(self.data.getvalue())
                root = pyzipper.Path(filename, pwd=self.pwd)
                self.addCleanup(root.root.close)
                self.assertIsInstance(root.root, pyzipper.AESZipFile)
                self.assertEqual(root.name, os.path.basename(str(filename)))
                self.assertEqual((root / 'b/d/e.txt').read_bytes(), b'content of e')

    def test_pickle(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        filename = os.path.join(tmpdir, 'abcde.zip')
        with open(filename, 'wb') as f:
            f.write(self.data.getvalue())
        path = pyzipper.Path(filename) / 'b' / 'c.txt'
        self.addCleanup(path.root.close)
        restored = pickle.loads(pickle.dumps(path))
        self.addCleanup(restored.root.close)
        self.assertEqual(restored.at, 'b/c.txt')
        self.assertTrue(restored.exists())
        # The password is not part of the pickle.
        self.assertIsNone(restored.root.pwd)
        with restored.open('rb', pwd=self.pwd) as strm:
            self.assertEqual(strm.read(), b'content of c')

    def test_inject(self):
        data = io.BytesIO()
        with self.open_zip('w', file=data) as zf:
            zf.writestr('x/y/z.txt', b'content of z')
            _path.CompleteDirs.inject(zf)
        with self.open_zip(file=data) as zf:
            self.assertEqual(zf.namelist(), ['x/y/z.txt', 'x/y/', 'x/'])


class PlainZipFilePathTests(PlainZipFileMixin, PathTestsBase, unittest.TestCase):
    pass


class PlainAESZipFilePathTests(PlainAESZipFileMixin, PathTestsBase, unittest.TestCase):
    pass


class EncryptedPathTests(EncryptedMixin, PathTestsBase, unittest.TestCase):

    def test_traverse_without_password(self):
        """Listing needs no password, reading does."""
        zf = self.open_zip(set_pwd=False)
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf)
        self.assertEqual(sorted(p.name for p in root.iterdir()), ['a.txt', 'b', 'g'])
        self.assertTrue((root / 'b/d/e.txt').is_file())
        with self.assertRaises(RuntimeError):
            (root / 'a.txt').read_bytes()
        with self.assertRaises(RuntimeError):
            (root / 'a.txt').read_text(encoding='utf-8')

    def test_wrong_password(self):
        zf = self.open_zip(set_pwd=False)
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf, pwd=b'wrong')
        with self.assertRaises(RuntimeError):
            (root / 'a.txt').read_bytes()
        with self.assertRaises(RuntimeError):
            (root / 'a.txt').open('rb', pwd=b'also wrong')

    def test_pwd_argument(self):
        zf = self.open_zip(set_pwd=False)
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf, pwd=PWD)
        self.assertEqual(zf.pwd, PWD)
        self.assertEqual((root / 'b' / 'c.txt').read_bytes(), b'content of c')
        # navigating must not reset the password
        self.assertEqual((root / 'b' / 'd' / 'e.txt').parent.joinpath('e.txt').read_bytes(),
                         b'content of e')
        self.assertEqual(zf.pwd, PWD)

    def test_pwd_argument_type(self):
        zf = self.open_zip(set_pwd=False)
        self.addCleanup(zf.close)
        with self.assertRaises(TypeError):
            pyzipper.Path(zf, pwd='not bytes')

    def test_open_pwd(self):
        zf = self.open_zip(set_pwd=False)
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf)
        with (root / 'a.txt').open('rb', pwd=PWD) as strm:
            self.assertEqual(strm.read(), b'content of a')
        with (root / 'a.txt').open('r', encoding='utf-8', pwd=PWD) as strm:
            self.assertEqual(strm.read(), 'content of a')
        # a per-call password does not become the default
        self.assertIsNone(zf.pwd)

    def test_readable_by_plain_aes_zipfile(self):
        """Members written through a Path are regular WZ_AES members."""
        data = io.BytesIO()
        with self.open_zip('w', file=data) as zf:
            with (pyzipper.Path(zf) / 'new.txt').open('w', encoding='utf-8') as strm:
                strm.write('content of new')
        with pyzipper.AESZipFile(data) as zf:
            with self.assertRaises(RuntimeError):
                zf.read('new.txt')
            self.assertEqual(zf.read('new.txt', pwd=PWD), b'content of new')


class SubclassTests(unittest.TestCase):

    def test_user_subclass_is_preserved(self):
        class MyZipFile(pyzipper.AESZipFile):
            def marker(self):
                return 'mine'

        data = io.BytesIO()
        with MyZipFile(data, 'w') as zf:
            zf.writestr('a/b.txt', b'content of b')
        zf = MyZipFile(data)
        self.addCleanup(zf.close)
        root = pyzipper.Path(zf)
        self.assertIsInstance(root.root, MyZipFile)
        self.assertEqual(root.root.marker(), 'mine')
        self.assertEqual((root / 'a' / 'b.txt').read_bytes(), b'content of b')

    def test_stdlib_zipfile_object_is_rejected(self):
        """Only pyzipper zipfile objects (or filenames) are valid roots."""
        import zipfile
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as zf:
            zf.writestr('a.txt', b'content of a')
        with zipfile.ZipFile(data) as zf:
            with self.assertRaises(Exception):
                pyzipper.Path(zf)


if __name__ == '__main__':
    unittest.main()
