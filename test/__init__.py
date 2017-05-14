#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

#from . import run_src_app
#from run_src_app import run_app_test
#from run_src_app import makeTests

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


def alltests():
    # 2015-06-12 move to preptests target
    # makeTests()
    # run all tests
    ret = unittest.TestLoader().discover('test/haystack/')
    #import code
    #code.interact(local=locals())
    #print '*** REMOVING reverse tests ***'
    #for x in ret._tests:
    #    if 'reverse' in str(x):
    #        ret._tests.remove(x)

    return ret


#alltests = suite()

if __name__ == '__main__':
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
