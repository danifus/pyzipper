.. image:: https://img.shields.io/pypi/v/pyzipper.svg
        :target: https://pypi.org/project/pyzipper/
        :alt: Current Version on PyPi

.. image:: https://img.shields.io/pypi/pyversions/pyzipper.svg
        :target: https://pypi.org/project/pyzipper/
        :alt: Supported Python Versions


.. image:: https://img.shields.io/travis/danifus/pyzipper.svg
        :target: https://travis-ci.org/danifus/pyzipper
        :alt: Travis build (Linux/OsX)

.. image:: https://ci.appveyor.com/api/projects/status/github/danifus/pyzipper?svg=true
        :target: https://ci.appveyor.com/project/danifus/pyzipper/branch/master
        :alt: AppVeyor build (Windows)

.. image:: https://readthedocs.org/projects/pyzipper/badge/?version=latest
        :target: https://pyzipper.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/danifus/pyzipper/shield.svg
        :target: https://pyup.io/repos/github/danifus/pyzipper
        :alt: Updates

.. image:: https://coveralls.io/repos/github/danifus/pyzipper/badge.svg?branch=master
        :target: https://coveralls.io/github/danifus/pyzipper?branch=master
        :alt: Code Coverage


pyzipper
========

Modification of Python's ``zipfile`` to read and write AES encrypted zip files.

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
       zf.pwd = secret_password
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")

   with pyzipper.AESZipFile('new_test.zip') as zf:
       zf.pwd = secret_password
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
       zf.pwd = secret_password
       zf.setencryption(pyzipper.WZ_AES, nbits=128)
       zf.writestr('test.txt', "What ever you do, don't tell anyone!")

   with pyzipper.AESZipFile('new_test.zip') as zf:
       zf.pwd = secret_password
       my_secrets = zf.read('test.txt')


Credits
-------

The docs skeleton was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
