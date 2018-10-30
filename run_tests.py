import sys
import unittest


do_zipfile64 = False
if len(sys.argv) > 1:
    if sys.argv[1] == 'extralargefile':
        do_zipfile64 = True


names = [
    'test.test_zipfile',
]

if do_zipfile64:
    names.append('test.test_zipfile64')

suite = unittest.TestLoader().loadTestsFromNames(names)
unittest.TextTestRunner(verbosity=2).run(suite)
