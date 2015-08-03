#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module."""

import unittest
import os

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

def load_tests(loader, standard_tests, pattern):
    print '*** do not test reverse ***'
    # top level directory cached on loader instance
    this_dir = os.path.dirname(__file__)
    #package_tests = loader.discover(start_dir=this_dir, pattern=pattern)
    #standard_tests.addTests(package_tests)
    return standard_tests


if __name__ == '__main__':
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
