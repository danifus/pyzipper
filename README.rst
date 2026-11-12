pyzipper
========

A replacement for Python's ``zipfile`` that can read and write AES encrypted
zip files. Forked from Python 3.7's ``zipfile`` module, it features the same
``zipfile`` API from that time (most notably, lacking support for
``pathlib``-compatible wrappers that were introduced in Python 3.8).

Installation
------------

.. code-block:: bash

   pip install pyzipper


Usage
-----

.. code-block:: python

   import pyzipper

   secret_password = b'lost art of keeping a secret'

   with pyzipper.AESZipFile('new_test.zip',
                            'w',
                            compression=pyzipper.ZIP_LZMA,
                            encryption=pyzipper.WZ_AES) as zf:
       zf.setpassword(secret_password)
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")

   with pyzipper.AESZipFile('new_test.zip') as zf:
       zf.setpassword(secret_password)
       my_secrets = zf.read('test.txt')

``pyzipper.Path`` gives a ``pathlib``-like interface to the members of an
archive. It is the equivalent of ``zipfile.Path`` from the standard library
with support for encrypted archives (requires Python 3.8+):

.. code-block:: python

   root = pyzipper.Path('new_test.zip', pwd=secret_password)

   for path in root.iterdir():
       print(path.name, path.is_dir())

   my_secrets = (root / 'test.txt').read_text(encoding='utf-8')

``Path`` accepts a filename or an existing ``pyzipper.ZipFile`` /
``AESZipFile`` object. ``pwd`` sets the default password of the underlying
zipfile, like ``setpassword()``; a password for a single member can be passed
with ``path.open('rb', pwd=...)``. Listing and traversing an archive does not
need the password, only reading or writing members does.


CRC32 Values
------------

From pyzipper v0.4.0 onwards, no CRC32 values are included in the file headers
by default. Prior to v0.4.0 (2026-05-13), a bug resulted in CRC32 values
erroneously being included for small files (<20 uncompressed bytes).

From the `WZ AES FAQ`_ about CRC values:

    Within the Zip format, the primary use of the CRC value is to detect accidental corruption of data that has been stored in the Zip file. With files encrypted according to the Zip 2.0 encryption specification, it also functions to some extent as a method of detecting deliberate attempts to modify the encrypted data, but not one that can be considered cryptographically strong. The CRC is not needed for these purposes with the WinZip AES encryption specification, where the HMAC-SHA1-based authentication code instead serves these roles.

    The CRC has a drawback in that for very small files, such as files with four or fewer bytes, the CRC can be used, independent of the encryption algorithm, to determine the unencrypted contents of the file. And, in general, it is preferable to store as little information as possible about the encrypted file in the unencrypted Zip headers.

    The CRC does serve one purpose that the authentication code does not. The CRC is computed based on the original uncompressed, unencrypted contents of the file, and it is checked after the file has been decrypted and decompressed. In contrast, the authentication code used with WinZip AES encryption is computed after compression/encryption and it is checked before decryption/decompression. In the very rare event of a hardware or software error that corrupts data during compression and encryption, or during decryption and decompression, the CRC will catch the error, but the authentication code will not.

You can conditionally enable the inclusion of the CRC32 values for files with
at least ``min_bytes_to_include_crc`` uncompressed bytes using the
following code:

.. code-block:: python

   with pyzipper.AESZipFile(
       'new_test.zip',
       'w',
       compression=pyzipper.ZIP_LZMA,
   ) as zf:
       zf.setencryption(
           pyzipper.WZ_AES,
           conditionally_include_crc=True,
           min_bytes_to_include_crc=<minimum uncompressed bytes to include crc>,
       )
       ...

The lowest number of bytes ``min_bytes_to_include_crc`` may be set to is
``20``, as in `WZ AES FAQ`_.


AES Strength
------------

The strength of the AES encryption can be configure to be 128, 192 or 256 bits.
By default it is 256 bits. Use the ``setencryption()`` method to specify the
encryption kwargs:

.. code-block:: python

   import pyzipper

   secret_password = b'lost art of keeping a secret'

   with pyzipper.AESZipFile('new_test.zip',
                            'w',
                            compression=pyzipper.ZIP_LZMA) as zf:
       zf.setpassword(secret_password)
       zf.setencryption(pyzipper.WZ_AES, nbits=256)
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")

   with pyzipper.AESZipFile('new_test.zip') as zf:
       zf.setpassword(secret_password)
       my_secrets = zf.read('test.txt')

Documentation
-------------

Official Python ZipFile documentation is available here: https://docs.python.org/3/library/zipfile.html

Credits
-------

The docs skeleton was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`WZ AES FAQ`: https://www.winzip.com/en/support/aes-encryption/#crc-faq
