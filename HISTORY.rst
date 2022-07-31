=======
History
=======

0.3.6 (2022-07-31)
------------------
* Exclude test, not tests, from setup.py packaging


0.3.5 (2021-04-08)
------------------
* Update trove classifiers to include python 3.8 and 3.9
* Update tests to use github actions

0.3.4 (2020-12-24)
------------------

* Fix HMAC check when all filesize bytes have been decompressed but bytes
  remain in the lzma stream

0.3.3 (2020-06-18)
------------------

* Add extra exception message when user supplies non-bytes password
* Fix reading zip64 extra when disk num entry is present
* Add BadZipFile errors for invalid zip64 extra fields

0.3.1 (2018-11-17)
------------------

* Add support for Python 3.4, 3.5
* Add travis ci integration.
* Fix bug in local file header record.

0.2.0 (2018-11-17)
------------------

* Second release on PyPI.

0.1.0 (2018-11-07)
------------------

* First release on PyPI.
