import io
import os
import struct
import time
import unittest
from random import randint, random

from test.support import unlink
from .test_zipfile import (
    TESTFN, TESTFN2, get_files, requires_bz2, requires_zlib, requires_lzma,
)

from pyzipper import zipfile
from pyzipper import zipfile_aes


FIXEDTEST_SIZE = 1000


try:
    import Crypto
except ImportError:
    Crypto = None

requires_pycrypto = unittest.skipUnless(Crypto, 'requires pycrypto')


@requires_pycrypto
class WZAESKnownFileTests(unittest.TestCase):
    """Test decryption against invariant files for behaviour.

    Once we know that we can decrypt a file known for a particular behaviour,
    we have confidence that files encrypted with the library, which are also
    able to be decrypted, are also good. In essence, this is a sanity check to
    make sure that we don't have a bug in both the encryption and decryption
    routines which allows the library to encrypt / decrypt files it has
    written but which are not compatible with other implementations.
    """

    def tearDown(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def test_decrypt_known_good(self):
        """Decrypting a known good file works."""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            content = zipfp.read('test.txt', pwd=b'test')
        self.assertEqual(content, b'This is a test file for AES encryption.')

    def test_decrypt_bad_password_fails(self):
        """Decrypting a file with a bad password raises an error."""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\x00\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad password for file %r" % fname
            with self.assertRaises(RuntimeError, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_hmac_ae1(self):
        """Decrypting an encrypted AE-1 file with a bad HMAC raises BadZipFile"""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<ZC\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<ZC\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad HMAC check for file %r" % 'test.txt'
            with self.assertRaises(zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_hmac_ae2(self):
        """Decrypting an encrypted AE-2 file with a bad HMAC raises BadZipFile"""
        data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00\x00\x00\x00\x00C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb0\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'\x00\x00\x00\x00C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad HMAC check for file %r" % 'test.txt'
            with self.assertRaises(zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_bad_crc_ae1(self):
        """Decrypting an encrypted AE-1 with a bad CRC raises BadZipFile"""
        bad_crc_ae_1_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x01\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<0C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x01\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_1_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad CRC-32 for file %r" % 'test.txt'
            with self.assertRaises(
                    zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')

    def test_decrypt_zero_crc_ae2(self):
        """Decrypting an encrypted AE-2 file with 0 CRC.

        CRC is not supposed to be used for AE-2 encryption and should be set
        to 0.
        """
        bad_crc_ae_2_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00\x00\x00\x00\x00C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'\x00\x00\x00\x00C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_2_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            content = zipfp.read('test.txt', pwd=b'test')
        self.assertEqual(content, b'This is a test file for AES encryption.')

    def test_decrypt_bad_crc_ae2(self):
        """Decrypting an encrypted AE-2 with an incorrect non-zero CRC raises
        BadZipFile.

        CRC is not supposed to be used for AE-2 encryption and should be set
        to 0 but in the case where it is provided, let's make sure it matches.
        """
        bad_crc_ae_2_data = (
            b'PK\x03\x04\x14\x00\x01\x00c\x00\x00\x00!\x00&[<0C\x00\x00\x00'
            b'\'\x00\x00\x00\x08\x00\x0b\x00test.txt\x01\x99\x07\x00\x02\x00AE'
            b'\x03\x00\x00\xe5G\xf2Z"[\xd0\xce\x96\xb7\xb3\xf6\x85\x8f|\x05'
            b'\xa9\xdaBGz:!\xde\xa6\x9a\xb7\x81A\x8e\x82\xfd)6|\x84\xf93\x0ecU'
            b'\xa7\x07v\xe19\x18A\x94GmQ\xc5Y\x12\xb0\x05=\xbb\xd2\x9bi\x873'
            b'\xb9\xbd\xf1PK\x01\x02\x14\x03\x14\x00\x01\x00c\x00\x00\x00!\x00'
            b'&[<0C\x00\x00\x00\'\x00\x00\x00\x08\x00\x0b\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00test.txt\x01\x99\x07\x00'
            b'\x02\x00AE\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
            b'A\x00\x00\x00t\x00\x00\x00\x00\x00'
        )
        fname = TESTFN
        with open(fname, "wb") as fp:
            fp.write(bad_crc_ae_2_data)

        with zipfile_aes.AESZipFile(fname, "r") as zipfp:
            exception_msg = "Bad CRC-32 for file %r" % 'test.txt'
            with self.assertRaises(
                    zipfile_aes.BadZipFile, msg=exception_msg):
                zipfp.read('test.txt', pwd=b'test')


@requires_pycrypto
class WZAESTests(unittest.TestCase):

    def tearDown(self):
        try:
            unlink(TESTFN)
        except FileNotFoundError:
            pass

    def test_write_password_required(self):
        """Not supplying a password when encrypting raises a RuntimeError"""
        fname = TESTFN
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setencryption(zipfile_aes.WZ_AES)
            with self.assertRaises(
                    RuntimeError,
                    msg='%s encryption requires a password.' % zipfile_aes.WZ_AES
            ):
                zipfp.open('test', 'w')

    def test_read_password_required(self):
        """Not supplying a password when decrypting raises a RuntimeError"""
        fname = TESTFN
        pwd = b'passwd'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(zipfile_aes.WZ_AES)
            zipfp.writestr('test.txt', 'content')

        with zipfile_aes.AESZipFile(fname) as zipfp:
            self.assertRaises(RuntimeError, zipfp.read, 'test.txt')

    def do_test_force_wz_aes_version(self, force_wz_aes_version):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                force_wz_aes_version=force_wz_aes_version
            )
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zinfo = zipfp.NameToInfo[content_fname]
            zipfp.setpassword(pwd)
            self.assertEqual(zinfo.wz_aes_version, force_wz_aes_version)
            read_content = zipfp.read(content_fname)
            self.assertEqual(content, read_content)

    def test_force_wz_aes_version(self):
        """Supplying force_wz_aes_version overrides the calculated version."""
        # One of these will fail if not overridden based on identical content.
        self.do_test_force_wz_aes_version(force_wz_aes_version=1)
        self.do_test_force_wz_aes_version(force_wz_aes_version=2)

    def do_test_aes_strength(self, nbits):
        """Providing an `nbits` encryption kwarg changes the encryption strength.

        Checks that we can encrypt then decrypt and that the compressed size is
        as expected for the varying salt length.
        """
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(fname, "w") as zipfp:
            zipfp.setpassword(pwd)
            zipfp.setencryption(
                zipfile_aes.WZ_AES,
                nbits=nbits
            )
            with zipfp.open(content_fname, 'w') as zopen:
                zopen.write(content)

        salt_lengths = {
            128: 8,
            192: 12,
            256: 16,
        }

        def expected_compress_size(content, nbits):
            """Computes the expected compress_size for a STORED file for nbits
            encryption."""
            return (
                len(content)
                + salt_lengths[nbits]
                + 2   # pwd_verify_length
                + 10  # mac_length
            )

        expected_strength = {
            128: 1,
            192: 2,
            256: 3,
        }

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zinfo = zipfp.NameToInfo[content_fname]
            zipfp.setpassword(pwd)
            read_content = zipfp.read(content_fname)
            self.assertEqual(content, read_content)
            self.assertEqual(zinfo.wz_aes_strength, expected_strength[nbits])
            self.assertEqual(
                zinfo.compress_size,
                expected_compress_size(content, nbits)
            )

    def test_aes_strengths(self):
        self.do_test_aes_strength(nbits=128)
        self.do_test_aes_strength(nbits=192)
        self.do_test_aes_strength(nbits=256)

    def test_aes_invalid_strength(self):
        with self.assertRaises(RuntimeError):
            self.do_test_aes_strength(nbits='not correct')

    def test_aes_encryption_via_init(self):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(
                fname,
                mode='w',
                encryption=zipfile_aes.WZ_AES) as zipfp:
            zipfp.setpassword(pwd)
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zipfp.setpassword(pwd)
            read_content = zipfp.read(content_fname)

        self.assertEqual(content, read_content)

    def test_aes_encryption_via_init_with_kwargs(self):
        fname = TESTFN
        pwd = b'passwd'
        content_fname = 'test.txt'
        content = b'content'
        with zipfile_aes.AESZipFile(
                fname,
                'w',
                encryption=zipfile_aes.WZ_AES,
                encryption_kwargs={'nbits': 128}
        ) as zipfp:
            zipfp.setpassword(pwd)
            zipfp.writestr(content_fname, content)

        with zipfile_aes.AESZipFile(fname) as zipfp:
            zipfp.setpassword(pwd)
            zinfo = zipfp.NameToInfo[content_fname]
            wz_aes_strength = zinfo.wz_aes_strength
            read_content = zipfp.read(content_fname)

        self.assertEqual(wz_aes_strength, 1)
        self.assertEqual(content, read_content)

    def test_seek_tell(self):
        # Test seek functionality
        txt = b"Where's Bruce?"
        bloc = txt.find(b"Bruce")
        pwd = b'passwd'
        # Check seek on a file
        with zipfile_aes.AESZipFile(TESTFN, "w") as zipf:
            zipf.pwd = pwd
            zipf.setencryption(zipfile_aes.WZ_AES, nbits=128)
            zipf.writestr("foo.txt", txt)
        with zipfile_aes.AESZipFile(TESTFN, "r") as zipf:
            zipf.pwd = pwd
            with zipf.open("foo.txt", "r") as fp:
                fp.seek(bloc, os.SEEK_SET)
                self.assertEqual(fp.tell(), bloc)
                fp.seek(-bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), bloc)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])
                fp.seek(0, os.SEEK_END)
                self.assertEqual(fp.tell(), len(txt))
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)

        # Check seek on memory file
        data = io.BytesIO()
        with zipfile_aes.AESZipFile(data, mode="w") as zipf:
            zipf.pwd = pwd
            zipf.setencryption(zipfile_aes.WZ_AES, nbits=128)
            zipf.writestr("foo.txt", txt)
        with zipfile_aes.AESZipFile(data, mode="r") as zipf:
            zipf.pwd = pwd
            with zipf.open("foo.txt", "r") as fp:
                fp.seek(bloc, os.SEEK_SET)
                self.assertEqual(fp.tell(), bloc)
                fp.seek(-bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.tell(), bloc)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])

                # Make sure that the second read after seeking back beyond
                # _readbuffer returns the same content (ie. rewind to the start of
                # the file to read forward to the required position).
                old_read_size = fp.MIN_READ_SIZE
                fp.MIN_READ_SIZE = 1
                fp._readbuffer = b''
                fp._offset = 0
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)
                fp.seek(bloc, os.SEEK_CUR)
                self.assertEqual(fp.read(5), txt[bloc:bloc+5])
                fp.MIN_READ_SIZE = old_read_size

                fp.seek(0, os.SEEK_END)
                self.assertEqual(fp.tell(), len(txt))
                fp.seek(0, os.SEEK_SET)
                self.assertEqual(fp.tell(), 0)

                # Read the file completely to definitely call any eof integrity
                # checks (hmac/crc) and make sure they still pass.
                fp.read()


class AbstractTestsWithRandomBinaryFiles:
    compression = None
    encryption = None
    pwd = None
    encryption_kwargs = None

    @classmethod
    def setUpClass(cls):
        datacount = randint(16, 64)*1024 + randint(1, 1024)
        cls.data = b''.join(struct.pack('<f', random()*randint(-1000, 1000))
                            for i in range(datacount))

    def setUp(self):
        # Make a source file with some lines
        with open(TESTFN, "wb") as fp:
            fp.write(self.data)

    def tearDown(self):
        unlink(TESTFN)
        unlink(TESTFN2)

    def set_pwd_if_needed(self, zipfp):
        if self.encryption and self.pwd:
            zipfp.setpassword(self.pwd)

    def make_test_archive(self, f, compression):
        # Create the ZIP archive
        with zipfile_aes.AESZipFile(f, "w", compression) as zipfp:
            if self.encryption:
                if self.pwd:
                    zipfp.setpassword(self.pwd)
                if self.encryption_kwargs:
                    encryption_kwargs = self.encryption_kwargs
                else:
                    encryption_kwargs = {}
                zipfp.setencryption(
                    self.encryption,
                    **encryption_kwargs
                )
            zipfp.write(TESTFN, "another.name")
            zipfp.write(TESTFN, TESTFN)

    def zip_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            testdata = zipfp.read(TESTFN)
            self.assertEqual(len(testdata), len(self.data))
            self.assertEqual(testdata, self.data)
            self.assertEqual(zipfp.read("another.name"), self.data)

    def test_read(self):
        for f in get_files(self):
            self.zip_test(f, self.compression)

    def zip_open_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zipdata1 = []
            with zipfp.open(TESTFN) as zipopen1:
                while True:
                    read_data = zipopen1.read(256)
                    if not read_data:
                        break
                    zipdata1.append(read_data)

            zipdata2 = []
            with zipfp.open("another.name") as zipopen2:
                while True:
                    read_data = zipopen2.read(256)
                    if not read_data:
                        break
                    zipdata2.append(read_data)

            testdata1 = b''.join(zipdata1)
            self.assertEqual(len(testdata1), len(self.data))
            self.assertEqual(testdata1, self.data)

            testdata2 = b''.join(zipdata2)
            self.assertEqual(len(testdata2), len(self.data))
            self.assertEqual(testdata2, self.data)

    def test_open(self):
        for f in get_files(self):
            self.zip_open_test(f, self.compression)

    def zip_random_open_test(self, f, compression):
        self.make_test_archive(f, compression)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zipdata1 = []
            with zipfp.open(TESTFN) as zipopen1:
                while True:
                    read_data = zipopen1.read(randint(1, 1024))
                    if not read_data:
                        break
                    zipdata1.append(read_data)

            testdata = b''.join(zipdata1)
            self.assertEqual(len(testdata), len(self.data))
            self.assertEqual(testdata, self.data)

    def test_random_open(self):
        for f in get_files(self):
            self.zip_random_open_test(f, self.compression)


@requires_pycrypto
class WZAESStoredTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                            unittest.TestCase):
    compression = zipfile.ZIP_STORED
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_zlib
class WZAESDeflateTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                             unittest.TestCase):
    compression = zipfile.ZIP_DEFLATED
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_bz2
class WZAESBzip2TestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                           unittest.TestCase):
    compression = zipfile.ZIP_BZIP2
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


@requires_pycrypto
@requires_lzma
class WZAESLzmaTestsWithRandomBinaryFiles(AbstractTestsWithRandomBinaryFiles,
                                          unittest.TestCase):
    compression = zipfile.ZIP_LZMA
    encryption = zipfile_aes.WZ_AES
    pwd = b'this is a test password'


class AbstractTestZip64InSmallFiles:
    # These tests test the ZIP64 functionality without using large files,
    # see test_zipfile64 for proper tests.

    @classmethod
    def setUpClass(cls):
        line_gen = (bytes("Test of zipfile line %d." % i, "ascii")
                    for i in range(0, FIXEDTEST_SIZE))
        cls.data = b'\n'.join(line_gen)

    def setUp(self):
        self._limit = zipfile.ZIP64_LIMIT
        self._filecount_limit = zipfile.ZIP_FILECOUNT_LIMIT
        zipfile.ZIP64_LIMIT = 1000
        zipfile.ZIP_FILECOUNT_LIMIT = 9

        # Make a source file with some lines
        with open(TESTFN, "wb") as fp:
            fp.write(self.data)

    def set_pwd_if_needed(self, zipfp):
        if self.encryption and self.pwd:
            zipfp.setpassword(self.pwd)

    def start_encryption(self, zipfp):
        if self.encryption:
            if self.pwd:
                zipfp.setpassword(self.pwd)
                if self.encryption_kwargs:
                    encryption_kwargs = self.encryption_kwargs
                else:
                    encryption_kwargs = {}
                zipfp.setencryption(
                    self.encryption,
                    **encryption_kwargs
                )

    def zip_test(self, f, compression):
        # Create the ZIP archive
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.write(TESTFN, "another.name")
            zipfp.write(TESTFN, TESTFN)
            zipfp.writestr("strfile", self.data)

        # Read the ZIP archive
        with zipfile_aes.AESZipFile(f, "r", compression) as zipfp:
            self.set_pwd_if_needed(zipfp)
            self.assertEqual(zipfp.read(TESTFN), self.data)
            self.assertEqual(zipfp.read("another.name"), self.data)
            self.assertEqual(zipfp.read("strfile"), self.data)

            # Print the ZIP directory
            fp = io.StringIO()
            zipfp.printdir(fp)

            directory = fp.getvalue()
            lines = directory.splitlines()
            self.assertEqual(len(lines), 4) # Number of files + header

            self.assertIn('File Name', lines[0])
            self.assertIn('Modified', lines[0])
            self.assertIn('Size', lines[0])

            fn, date, time_, size = lines[1].split()
            self.assertEqual(fn, 'another.name')
            self.assertTrue(time.strptime(date, '%Y-%m-%d'))
            self.assertTrue(time.strptime(time_, '%H:%M:%S'))
            self.assertEqual(size, str(len(self.data)))

            # Check the namelist
            names = zipfp.namelist()
            self.assertEqual(len(names), 3)
            self.assertIn(TESTFN, names)
            self.assertIn("another.name", names)
            self.assertIn("strfile", names)

            # Check infolist
            infos = zipfp.infolist()
            names = [i.filename for i in infos]
            self.assertEqual(len(names), 3)
            self.assertIn(TESTFN, names)
            self.assertIn("another.name", names)
            self.assertIn("strfile", names)
            for i in infos:
                self.assertEqual(i.file_size, len(self.data))

            # check getinfo
            for nm in (TESTFN, "another.name", "strfile"):
                info = zipfp.getinfo(nm)
                self.assertEqual(info.filename, nm)
                self.assertEqual(info.file_size, len(self.data))

            # Check that testzip doesn't raise an exception
            zipfp.testzip()

    def test_basic(self):
        for f in get_files(self):
            self.zip_test(f, self.compression)

    def test_too_many_files(self):
        # This test checks that more than 64k files can be added to an archive,
        # and that the resulting archive can be read properly by ZipFile
        zipf = zipfile_aes.AESZipFile(TESTFN, "w", self.compression,
                                      allowZip64=True)
        zipf.debug = 100
        numfiles = 15
        for i in range(numfiles):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf2 = zipfile_aes.AESZipFile(TESTFN, "r", self.compression)
        self.assertEqual(len(zipf2.namelist()), numfiles)
        for i in range(numfiles):
            content = zipf2.read("foo%08d" % i).decode('ascii')
            self.assertEqual(content, "%d" % (i**3 % 57))
        zipf2.close()

    def test_too_many_files_append(self):
        zipf = zipfile_aes.AESZipFile(TESTFN, "w", self.compression,
                                      allowZip64=False)
        zipf.debug = 100
        numfiles = 9
        for i in range(numfiles):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles)
        with self.assertRaises(zipfile.LargeZipFile):
            zipf.writestr("foo%08d" % numfiles, b'')
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf = zipfile_aes.AESZipFile(TESTFN, "a", self.compression,
                                      allowZip64=False)
        zipf.debug = 100
        self.assertEqual(len(zipf.namelist()), numfiles)
        with self.assertRaises(zipfile.LargeZipFile):
            zipf.writestr("foo%08d" % numfiles, b'')
        self.assertEqual(len(zipf.namelist()), numfiles)
        zipf.close()

        zipf = zipfile_aes.AESZipFile(TESTFN, "a", self.compression,
                                      allowZip64=True)
        zipf.debug = 100
        self.assertEqual(len(zipf.namelist()), numfiles)
        numfiles2 = 15
        for i in range(numfiles, numfiles2):
            zipf.writestr("foo%08d" % i, "%d" % (i**3 % 57))
        self.assertEqual(len(zipf.namelist()), numfiles2)
        zipf.close()

        zipf2 = zipfile_aes.AESZipFile(TESTFN, "r", self.compression)
        self.assertEqual(len(zipf2.namelist()), numfiles2)
        for i in range(numfiles2):
            content = zipf2.read("foo%08d" % i).decode('ascii')
            self.assertEqual(content, "%d" % (i**3 % 57))
        zipf2.close()

    def tearDown(self):
        zipfile.ZIP64_LIMIT = self._limit
        zipfile.ZIP_FILECOUNT_LIMIT = self._filecount_limit
        unlink(TESTFN)
        unlink(TESTFN2)


class StoredTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                  unittest.TestCase):
    compression = zipfile.ZIP_STORED
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'

    def large_file_exception_test(self, f, compression):
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=False) as zipfp:
            self.start_encryption(zipfp)
            self.assertRaises(zipfile.LargeZipFile,
                              zipfp.write, TESTFN, "another.name")

    def large_file_exception_test2(self, f, compression):
        with zipfile_aes.AESZipFile(f, "w", compression, allowZip64=False) as zipfp:
            self.start_encryption(zipfp)
            self.assertRaises(zipfile.LargeZipFile,
                              zipfp.writestr, "another.name", self.data)

    def test_large_file_exception(self):
        for f in get_files(self):
            self.large_file_exception_test(f, zipfile.ZIP_STORED)
            self.large_file_exception_test2(f, zipfile.ZIP_STORED)

    def test_absolute_arcnames(self):
        with zipfile_aes.AESZipFile(TESTFN2, "w", zipfile.ZIP_STORED,
                                    allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.write(TESTFN, "/absolute")

        with zipfile_aes.AESZipFile(TESTFN2, "r", zipfile.ZIP_STORED) as zipfp:
            self.set_pwd_if_needed(zipfp)
            self.assertEqual(zipfp.namelist(), ["absolute"])

    def test_append(self):
        # Test that appending to the Zip64 archive doesn't change
        # extra fields of existing entries.
        with zipfile_aes.AESZipFile(TESTFN2, "w", allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.writestr("strfile", self.data)
        with zipfile_aes.AESZipFile(TESTFN2, "r", allowZip64=True) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zinfo = zipfp.getinfo("strfile")
            extra = zinfo.extra
        with zipfile_aes.AESZipFile(TESTFN2, "a", allowZip64=True) as zipfp:
            self.start_encryption(zipfp)
            zipfp.writestr("strfile2", self.data)
        with zipfile_aes.AESZipFile(TESTFN2, "r", allowZip64=True) as zipfp:
            self.set_pwd_if_needed(zipfp)
            zinfo = zipfp.getinfo("strfile")
            self.assertEqual(zinfo.extra, extra)


@requires_zlib
class DeflateTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                   unittest.TestCase):
    compression = zipfile.ZIP_DEFLATED
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


@requires_bz2
class Bzip2TestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                 unittest.TestCase):
    compression = zipfile.ZIP_BZIP2
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


@requires_lzma
class LzmaTestZip64InSmallFiles(AbstractTestZip64InSmallFiles,
                                unittest.TestCase):
    compression = zipfile.ZIP_LZMA
    encryption = zipfile_aes.WZ_AES
    encryption_kwargs = {'nbits': 128}
    pwd = b'this is a test password'


if __name__ == "__main__":
    unittest.main()
