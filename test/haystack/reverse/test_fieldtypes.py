#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import struct
import operator
import os
import unittest
import pickle
import sys

from haystack.config import Config
from haystack.reverse import structure, fieldtypes
from haystack.reverse import reversers
from haystack.reverse.heuristics.dsa import *

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

log = logging.getLogger('test_fieldtypes')

class TestField(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = None #reversers.getContext('test/src/test-ctypes3.dump')
    self._putty7124 = None
    self.dsa = DSASimple()
    
  def setUp(self):  
    pass

  def tearDown(self):
    pass
  
  @property
  def putty7124(self):
    if self._putty7124 is None:
      self._putty7124 = reversers.getContext('test/dumps/putty/putty.7124.dump')
    return self._putty7124
  
  

if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


