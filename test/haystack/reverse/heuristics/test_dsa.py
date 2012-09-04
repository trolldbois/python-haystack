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
from haystack.reverse import fieldtypes
from haystack.reverse.fieldtypes import FieldType
from haystack.reverse.heuristics.dsa import *

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

log = logging.getLogger('test_field_analyzer')

class TestFieldAnalyzer(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.test1 = FS('''\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00....''')
    self.test2 = FS('''....\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00''')
    self.test3 = FS('''....1234aaaa.....''')
    self.test4 = FS('''\x00\x00\x00\x00h\x00i\x00 \x00m\x00y\x00 \x00n\x00a\x00m\x00e\x00\x00\x00\xef\x00\x00\x00\x00....''')
    self.zeroes = ZeroFields()
    self.strings = StringFields()
    pass    
  def setUp(self):  
    pass

  def tearDown(self):
    pass
  
  def test_zeroes(self):
    fields = self.zeroes.make_fields(self.test1, 0, len(self.test1))
    self.assertEquals( len(fields) , 3)
    self.assertEquals( fields[0].offset , 0)
    self.assertEquals( fields[0].size , 4)
    self.assertEquals( fields[1].offset , 8)
    self.assertEquals( fields[1].size , 8)
    self.assertEquals( fields[2].offset , 28)
    self.assertEquals( fields[2].size , 4)
    

class FS:
  def __init__(self, bytes, vaddr=0):
    self._bytes = bytes
    self._vaddr = vaddr
  def __len__(self):
    return len(self._bytes)
  @property
  def bytes(self):
    return self._bytes

if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


