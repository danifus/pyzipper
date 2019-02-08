=====
Usage
=====

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
