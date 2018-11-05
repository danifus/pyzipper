import sys
import unittest


names = []
if len(sys.argv) > 1:
    test_type = sys.argv[1]
    if test_type == 'extralargefile':
        names.append('test.test_zipfile64')
    elif test_type == 'aes':
        names.extend([
            'test.test_zipfile_aes',
            'test.test_zipfile2'
        ])
else:
    names.append('test.test_zipfile')

suite = unittest.TestLoader().loadTestsFromNames(names)
runner = unittest.TextTestRunner(verbosity=2).run(suite)
ret = not runner.wasSuccessful()
sys.exit(ret)
