import struct

from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Hash.SHA1 import SHA1Hash
from Cryptodome.Util import Counter
from Cryptodome import Random

from .zipfile import (
    ZIP_BZIP2,
    ZIP_LZMA,
    ZIP_STORED,
    BadZipFile,
    BaseZipDecrypter,
    ZipFile,
    ZipInfo,
    ZipExtFile,
)

WZ_AES = 'WZ_AES'
WZ_AES_COMPRESS_TYPE = 99
WZ_AES_V1 = 0x0001
WZ_AES_V2 = 0x0002
WZ_AES_VENDOR_ID = b'AE'

EXTRA_WZ_AES = 0x9901

WZ_SALT_LENGTHS = {
    1: 8,   # 128 bit
    2: 12,  # 192 bit
    3: 16,  # 256 bit
}
WZ_KEY_LENGTHS = {
    1: 16,  # 128 bit
    2: 24,  # 192 bit
    3: 32,  # 256 bit
}


class AESZipDecrypter(BaseZipDecrypter):

    hmac_size = 10

    def __init__(self, zinfo, pwd, encryption_header):
        self.filename = zinfo.filename

        key_length = WZ_KEY_LENGTHS[zinfo.wz_aes_strength]
        salt_length = WZ_SALT_LENGTHS[zinfo.wz_aes_strength]

        salt = struct.unpack(
            "<{}s".format(salt_length),
            encryption_header[:salt_length]
        )[0]
        pwd_verify_length = 2
        pwd_verify = encryption_header[salt_length:]
        dkLen = 2*key_length + pwd_verify_length
        keymaterial = PBKDF2(pwd, salt, count=1000, dkLen=dkLen)

        encpwdverify = keymaterial[2*key_length:]
        if encpwdverify != pwd_verify:
            raise RuntimeError("Bad password for file %r" % zinfo.filename)

        enckey = keymaterial[:key_length]
        self.decypter = AES.new(
            enckey,
            AES.MODE_CTR,
            counter=Counter.new(nbits=128, little_endian=True)
        )
        encmac_key = keymaterial[key_length:2*key_length]
        self.hmac = HMAC.new(encmac_key, digestmod=SHA1Hash())

    @staticmethod
    def encryption_header_length(zinfo):
        # salt_length + pwd_verify_length
        salt_length = WZ_SALT_LENGTHS[zinfo.wz_aes_strength]
        return salt_length + 2

    def decrypt(self, data):
        self.hmac.update(data)
        return self.decypter.decrypt(data)

    def check_hmac(self, hmac_check):
        if self.hmac.digest()[:10] != hmac_check:
            raise BadZipFile("Bad HMAC check for file %r" % self.filename)


class BaseZipEncrypter:

    def update_zipinfo(self, zipinfo):
        """Called when zip entry is opened for write and the encrypted is configured."""
        raise NotImplementedError(
            'BaseZipEncrypter implementations must implement `update_zipinfo`.'
        )

    def finalize_zipinfo(self, zipinfo):
        """Updates the zipinfo instance when the zip entry is being closed.

        It may be possible to update some fields based on information that
        wasn't available when update_zipinfo was called. This function should
        not change properties that would need to be written to the local file
        header if the underlying zip is not seekable as it isn't possible to
        return to the local file header to rewrite the new values.
        """
        raise NotImplementedError(
            'BaseZipEncrypter implementations must implement `finalize_zipinfo`.'
        )

    def encrypt(self, data):
        raise NotImplementedError(
            'BaseZipEncrypter implementations must implement `encrypt`.'
        )

    def encryption_header(self):
        raise NotImplementedError(
            'BaseZipEncrypter implementations must implement '
            '`encryption_header`.'
        )

    def flush(self):
        return b''


class AESZipEncrypter(BaseZipEncrypter):

    hmac_size = 10

    def __init__(
        self,
        pwd,
        nbits=256,
        force_wz_aes_version=None,
        conditionally_include_crc=None,
        min_bytes_to_include_crc=None,
    ):
        if not pwd:
            raise RuntimeError(
                '%s encryption requires a password.' % WZ_AES
            )

        if nbits not in (128, 192, 256):
            raise RuntimeError(
                "`nbits` must be one of 128, 192, 256. Got '%s'" % nbits
            )
        if conditionally_include_crc is not None:
            if (
                conditionally_include_crc is not True
                and conditionally_include_crc is not False
            ):
                raise ValueError(
                    "`conditionally_include_crc` must be True or False or None"
                )
            if conditionally_include_crc:
                if min_bytes_to_include_crc is None:
                    raise ValueError(
                        "`min_bytes_to_include_crc` must be set if `conditionally_include_crc` is True"  # noqa: E501
                    )
                if min_bytes_to_include_crc < 20:
                    raise ValueError(
                        "`min_bytes_to_include_crc` must be 20 or greater"
                    )
        if min_bytes_to_include_crc is not None and not conditionally_include_crc:
            raise ValueError(
                "`conditionally_include_crc` must be True if `min_bytes_to_include_crc` is set"
            )

        if force_wz_aes_version is not None:
            if force_wz_aes_version not in (WZ_AES_V1, WZ_AES_V2):
                raise ValueError(
                    "`force_wz_aes_version` must be WZ_AES_V1 (1) or WZ_AES_V2 (2)"
                )
            if conditionally_include_crc:
                raise ValueError(
                    "`force_wz_aes_version` and `conditionally_include_crc` must not be specified at the same time."  # noqa: E501
                )

        self.force_wz_aes_version = force_wz_aes_version
        self.conditionally_include_crc = conditionally_include_crc
        self.min_bytes_to_include_crc = min_bytes_to_include_crc
        salt_lengths = {
            128: 8,
            192: 12,
            256: 16,
        }
        self.salt_length = salt_lengths[nbits]
        key_lengths = {
            128: 16,
            192: 24,
            256: 32,
        }
        key_length = key_lengths[nbits]
        aes_strengths = {
            128: 1,
            192: 2,
            256: 3,
        }
        self.aes_strength = aes_strengths[nbits]

        self.salt = Random.new().read(self.salt_length)
        pwd_verify_length = 2
        dkLen = 2 * key_length + pwd_verify_length
        keymaterial = PBKDF2(pwd, self.salt, count=1000, dkLen=dkLen)

        self.encpwdverify = keymaterial[2*key_length:]

        enckey = keymaterial[:key_length]
        self.encrypter = AES.new(
            enckey,
            AES.MODE_CTR,
            counter=Counter.new(nbits=128, little_endian=True)
        )
        encmac_key = keymaterial[key_length:2*key_length]
        self.hmac = HMAC.new(encmac_key, digestmod=SHA1Hash())

    def compute_aes_version(self, zipinfo):
        # The only difference between version 1 and 2 is the
        # handling of the CRC values. For version 2 the CRC value
        # is not used and must be set to 0.
        # For small files, the CRC files can leak the contents of
        # the encrypted data.
        if self.force_wz_aes_version is not None:
            return self.force_wz_aes_version
        elif zipinfo.compress_type == ZIP_BZIP2:
            # For bzip2, the compression already has integrity checks
            # so CRC is not required.
            return WZ_AES_V2
        elif (
            self.conditionally_include_crc
            and zipinfo.file_size >= self.min_bytes_to_include_crc
        ):
            return WZ_AES_V1
        return WZ_AES_V2

    def update_zipinfo(self, zipinfo):
        zipinfo.wz_aes_vendor_id = WZ_AES_VENDOR_ID
        zipinfo.wz_aes_strength = self.aes_strength
        zipinfo.wz_aes_version = self.compute_aes_version(zipinfo)

    def finalize_zipinfo(self, zipinfo):
        # If we can't seek back, we have to keep the aes version we specified
        # when the local file header was written. If the file size is unknown,
        # this should be ae-2
        if not zipinfo.use_datadescripter:
            # We can go back and change the aes version we specified earlier.
            zipinfo.wz_aes_version = self.compute_aes_version(zipinfo)

    def encryption_header(self):
        return self.salt + self.encpwdverify

    def encrypt(self, data):
        data = self.encrypter.encrypt(data)
        self.hmac.update(data)
        return data

    def flush(self):
        return struct.pack('<%ds' % self.hmac_size, self.hmac.digest()[:10])


class AESZipInfo(ZipInfo):
    """Class with attributes describing each file in the ZIP archive."""

    # __slots__ on subclasses only need to contain the additional slots.
    __slots__ = (
        'wz_aes_version',
        'wz_aes_vendor_id',
        'wz_aes_strength',
        # 'wz_aes_actual_compression_type',
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wz_aes_version = None
        self.wz_aes_vendor_id = None
        self.wz_aes_strength = None

    def decode_extra_wz_aes(self, ln, extra):
        if ln == 7:
            counts = struct.unpack("<H2sBH", extra[4: ln+4])
        else:
            raise BadZipFile(
                "Corrupt extra field %04x (size=%d)" % (EXTRA_WZ_AES, ln))

        self.wz_aes_version = counts[0]
        self.wz_aes_vendor_id = counts[1]
        # 0x01  128-bit encryption key
        # 0x02  192-bit encryption key
        # 0x03  256-bit encryption key
        self.wz_aes_strength = counts[2]

        # the compression method is the one that would otherwise have been
        # stored in the local and central headers for the file. For example, if
        # the file is imploded, this field will contain the compression code 6.
        # This is needed because a compression method of 99 is used to indicate
        # the presence of an AES-encrypted file
        self.compress_type = counts[3]
        # self.wz_aes_actual_compression_type = counts[3]

    def get_extra_decoders(self):
        extra_decoders = super().get_extra_decoders()
        extra_decoders[EXTRA_WZ_AES] = self.decode_extra_wz_aes
        return extra_decoders

    def encode_extra(self, crc, compress_type):
        wz_aes_extra = b''
        if self.wz_aes_vendor_id is not None:
            compress_type = WZ_AES_COMPRESS_TYPE

            if self.wz_aes_version == WZ_AES_V2:
                crc = 0

            wz_aes_extra = struct.pack(
                "<3H2sBH",
                EXTRA_WZ_AES,
                7,  # extra block body length: H2sBH
                self.wz_aes_version,
                self.wz_aes_vendor_id,
                self.wz_aes_strength,
                self.compress_type,
            )
        return wz_aes_extra, crc, compress_type

    def encode_local_header(self, *, crc, compress_type, extra, **kwargs):
        wz_aes_extra, crc, compress_type = self.encode_extra(
            crc, compress_type)
        return super().encode_local_header(
            crc=crc,
            compress_type=compress_type,
            extra=extra+wz_aes_extra,
            **kwargs
        )

    def encode_central_directory(self, *, crc, compress_type, extra_data,
                                 **kwargs):
        wz_aes_extra, crc, compress_type = self.encode_extra(
            crc, compress_type)
        return super().encode_central_directory(
            crc=crc,
            compress_type=compress_type,
            extra_data=extra_data+wz_aes_extra,
            **kwargs)

    def encode_datadescripter(self, zip64, crc, compress_size, file_size):
        if self.wz_aes_version == WZ_AES_V2:
            crc = 0
        return super().encode_datadescripter(zip64, crc, compress_size, file_size)


class AESZipExtFile(ZipExtFile):

    def setup_aeszipdecrypter(self):
        if not self._pwd:
            raise RuntimeError(
                'File %r is encrypted with %s encryption and requires a '
                'password.' % (self.name, WZ_AES)
            )
        encryption_header_length = AESZipDecrypter.encryption_header_length(
            self._zinfo)
        self.encryption_header = self._fileobj.read(encryption_header_length)
        # Adjust read size for encrypted files since the start of the file
        # may be used for the encryption/password information.
        self._orig_compress_left -= encryption_header_length
        # Also remove the hmac length from the end of the file.
        self._orig_compress_left -= AESZipDecrypter.hmac_size

        return AESZipDecrypter

    def setup_decrypter(self):
        if self._zinfo.wz_aes_version is not None:
            return self.setup_aeszipdecrypter()
        return super().setup_decrypter()

    def check_wz_aes(self):
        # AES HMAC is calculated over the full encrypted compressed data stream.
        # Some decompressors may reach EOF / uncompressed size before all compressed
        # bytes have been consumed, so drain the remaining compressed bytes before
        # reading the 10-byte authentication code.
        while self._compress_left > 0:
            data = self._read2(self.MIN_READ_SIZE)
            if self._zinfo.compress_type == ZIP_STORED:
                if data:
                    raise BadZipFile(
                        "More data found than indicated by uncompressed size for "
                        "{!r}".format(self._zinfo.filename)
                    )
                continue

            extra_data = self._decompressor.decompress(data)
            if extra_data:
                raise BadZipFile(
                    "More data found than indicated by uncompressed size for "
                    "{!r}".format(self._zinfo.filename)
                )

        hmac_check = self._fileobj.read(self._decrypter.hmac_size)
        self._decrypter.check_hmac(hmac_check)

    def check_integrity(self):
        if self._zinfo.wz_aes_version is not None:
            self.check_wz_aes()
            if self._expected_crc is not None and self._expected_crc != 0:
                # Not part of the spec but still check the CRC if it is
                # supplied when WZ_AES_V2 is specified (no CRC check and CRC
                # should be 0).
                self.check_crc()
            elif self._zinfo.wz_aes_version != WZ_AES_V2:
                # CRC value should be 0 for AES vendor version 2.
                self.check_crc()
        else:
            super().check_integrity()


class AESZipFile(ZipFile):
    zipinfo_cls = AESZipInfo
    zipextfile_cls = AESZipExtFile

    def __init__(self, *args, **kwargs):
        encryption = kwargs.pop('encryption', None)
        encryption_kwargs = kwargs.pop('encryption_kwargs', None)
        super().__init__(*args, **kwargs)
        self.encryption = encryption
        self.encryption_kwargs = encryption_kwargs

    def get_encrypter(self):
        if self.encryption == WZ_AES:
            if self.encryption_kwargs is None:
                encryption_kwargs = {}
            else:
                encryption_kwargs = self.encryption_kwargs

            return AESZipEncrypter(pwd=self.pwd, **encryption_kwargs)
