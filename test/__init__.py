#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module."""

import unittest

from run_src_app import run_app_test
from run_src_app import makeTests

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

if __name__ == '__main__':
  print 'HEEEEEEEEELLOOO'
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
