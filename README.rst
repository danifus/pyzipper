.. image:: https://img.shields.io/pypi/v/pyzipper.svg
        :target: https://pypi.org/project/pyzipper/
        :alt: Current Version on PyPi

.. image:: https://img.shields.io/pypi/pyversions/pyzipper.svg
        :target: https://pypi.org/project/pyzipper/
        :alt: Supported Python Versions


pyzipper
========

A replacement for Python's ``zipfile`` that can read and write AES encrypted
zip files. Secure deletion of individual files from an existing ZIP archive
is also supported.

Forked from Python 3.7's ``zipfile`` module, it features the same
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
       zf.setencryption(pyzipper.WZ_AES, nbits=128)
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")

   with pyzipper.AESZipFile('new_test.zip') as zf:
       zf.setpassword(secret_password)
       my_secrets = zf.read('test.txt')


Partial Encryption
------------------

It is possible to create archives which contain a mixture of encrypted
and unencrypted files. This can be useful (for example) to include
clear-text documentation or recovery instructions, within an otherwise
secure archive.

To add a clear-text file to an otherwise encrypted archive, pass
``encrypt=False`` to ``open()``, ``write()`` or ``writestr()``.

.. code-block:: python

   import pyzipper

   secret_password = b'lost art of keeping a secret'

   with pyzipper.AESZipFile('new_test.zip',
                            'w',
                            compression=pyzipper.ZIP_LZMA) as zf:
       zf.setpassword(secret_password)
       zf.setencryption(pyzipper.WZ_AES, nbits=128)
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")
       zf.writestr('README.txt', "Secrets enclosed!", encrypt=False)


Deletion
--------

Deletion of individual files from within an existing archive is supported
via the ``ZipFile.delete(filename)`` method.

To replace an existing file, delete it first and then add a new one with
the same name.

Note that archives must be opened in with ``mode="a"`` (append), to allow
modifications. Deleting from archives opened for reading is not supported,
and opening with ``mode="w"`` or ``mode="x"`` will replace the entire ZIP
archive with an empty one (so there will be nothing to delete).

The algorithm used for deletion defaults to secure behavior, where data is
immediately overwritten with junk, then removed from the central directory
index, and finally (upon close) the archive is rewritten to reclaim space.

Secure deletion can be disabled by passing ``insecure_delete=True`` to the
``ZipFile`` or ``AESZipFie`` constructors.

It is possible to adjust how frequently the archive is rewritten, by passing
``compacting_threshold=X`` to the constructor, where X is a float between 0
and 1, representing how much of the archive can be "wasted space" before
triggering a compaction. Manual compaction is also available using the
``compact()`` method.


Documentation
-------------

Official Python ZipFile documentation is available here: https://docs.python.org/3/library/zipfile.html


Credits
-------

The docs skeleton was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
