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
from haystack.reverse import re_string

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

class TestReString(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = None #reversers.getContext('test/src/test-ctypes3.dump')

  def setUp(self):  
    pass

  def tearDown(self):
    pass

  def test_startsWithNulTerminatedString(self):
    uni = '''C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00j\x00a\x00l\x00\\\x00A\x00p\x00p\x00D\x00a\x00t\x00a\x00\\\x00R\x00o\x00a\x00m\x00i\x00n\x00g\x00\\\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\\\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00\\\x00Q\x00u\x00i\x00c\x00k\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00\\\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00.\x00i\x00n\x00i\x00\x00\x00'''
    size, codec, txt = re_string.startsWithNulTerminatedString(uni)
    self.assertEquals(size, len(uni) )
    
    pass

  def test_testEncoding(self):
    uni = '''C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00j\x00a\x00l\x00\\\x00A\x00p\x00p\x00D\x00a\x00t\x00a\x00\\\x00R\x00o\x00a\x00m\x00i\x00n\x00g\x00\\\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\\\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00\\\x00Q\x00u\x00i\x00c\x00k\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00\\\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00.\x00i\x00n\x00i\x00\x00\x00'''
    size, encoded = re_string.testEncoding(uni, 'utf-16le')
    self.assertEquals(size, len(uni) )

    x3 = '\x4C\x00\x6F\x00\xEF\x00\x63\x00\x20\x00\x4A\x00\x61\x00\x71\x00\x75\x00\x65\x00\x6D\x00\x65\x00\x74\x00\x00\x00'
    size, encoded = re_string.testEncoding(x3, 'utf-16le')
    self.assertEquals(size, len(x3) )

    pass

  def test_testAllEncodings(self):
    uni = '''C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00j\x00a\x00l\x00\\\x00A\x00p\x00p\x00D\x00a\x00t\x00a\x00\\\x00R\x00o\x00a\x00m\x00i\x00n\x00g\x00\\\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\\\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00\\\x00Q\x00u\x00i\x00c\x00k\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00\\\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00.\x00i\x00n\x00i\x00\x00\x00'''
    solutions = re_string.testAllEncodings(uni)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(uni) , '%s'%codec)

    x3 = '\x4C\x00\x6F\x00\xEF\x00\x63\x00\x20\x00\x4A\x00\x61\x00\x71\x00\x75\x00\x65\x00\x6D\x00\x65\x00\x74\x00\x00\x00'
    solutions = re_string.testAllEncodings(x3)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(x3) )

    pass



if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


