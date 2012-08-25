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
    self.test1 = '''C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00j\x00a\x00l\x00\\\x00A\x00p\x00p\x00D\x00a\x00t\x00a\x00\\\x00R\x00o\x00a\x00m\x00i\x00n\x00g\x00\\\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\\\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00\\\x00Q\x00u\x00i\x00c\x00k\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00\\\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00.\x00i\x00n\x00i\x00\x00\x00'''
    self.test2 = '''\x4C\x00\x6F\x00\xEF\x00\x63\x00\x20\x00\x4A\x00\x61\x00\x71\x00\x75\x00\x65\x00\x6D\x00\x65\x00\x74\x00\x00\x00'''
    self.test3 = '''\\\x00R\x00E\x00G\x00I\x00S\x00T\x00R\x00Y\x00\\\x00U\x00S\x00E\x00R\x00\\\x00S\x00-\x001\x00-\x005\x00-\x002\x001\x00-\x002\x008\x008\x004\x000\x006\x003\x000\x007\x003\x00-\x003\x003\x002\x009\x001\x001\x007\x003\x002\x000\x00-\x003\x008\x001\x008\x000\x003\x009\x001\x009\x009\x00-\x001\x000\x000\x000\x00_\x00C\x00L\x00A\x00S\x00S\x00E\x00S\x00\\\x00W\x00o\x00w\x006\x004\x003\x002\x00N\x00o\x00d\x00e\x00\\\x00C\x00L\x00S\x00I\x00D\x00\\\x00{\x007\x006\x007\x006\x005\x00B\x001\x001\x00-\x003\x00F\x009\x005\x00-\x004\x00A\x00F\x002\x00-\x00A\x00C\x009\x00D\x00-\x00E\x00A\x005\x005\x00D\x008\x009\x009\x004\x00F\x001\x00A\x00}\x00'''
    self.test4 = '''edrtfguyiopserdtyuhijo45567890oguiy4e65rtiu\x07\x08\x09\x00'''

  def setUp(self):  
    pass

  def tearDown(self):
    pass

  def test_startsWithNulTerminatedString(self):
    self.skipTest('')

    size, codec, txt = re_string.startsWithNulTerminatedString(self.test1)
    self.assertEquals(size, len(self.test1) )
    
    pass

  def test_try_decode_string(self):
    #self.skipTest('')
    
    size, codec, txt = re_string.try_decode_string(self.test1)
    self.assertEquals(size, len(self.test1) )

    size, codec, txt = re_string.try_decode_string(self.test2)
    self.assertEquals(size, len(self.test2) )

    size, codec, txt = re_string.try_decode_string(self.test3)
    self.assertEquals(size, len(self.test3) )

    size, codec, txt = re_string.try_decode_string(self.test4)
    self.assertEquals(size, len(self.test4)-4 )
    
    pass

  def test_testEncoding(self):
    self.skipTest('')

    uni = self.test1
    size, encoded = re_string.testEncoding(uni, 'utf-16le')
    self.assertEquals(size, len(uni) )

    x3 = self.test2
    size, encoded = re_string.testEncoding(x3, 'utf-16le')
    self.assertEquals(size, len(x3) )

    size, encoded = re_string.testEncoding(self.test4, 'utf-16le')
    self.assertEquals(size, -1 )
    size, encoded = re_string.testEncoding(self.test4, 'utf-8')
    self.assertEquals(size, len(self.test4) )

    pass

  def test_testAllEncodings(self):

    self.skipTest('')

    uni = self.test1
    solutions = re_string.testAllEncodings(uni)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(uni) , '%s'%codec)

    x3 = self.test2
    solutions = re_string.testAllEncodings(x3)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(x3) )
    
    solutions = re_string.testAllEncodings(self.test3)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(self.test3) )

    solutions = re_string.testAllEncodings(self.test4)
    size, codec, encoded = solutions[0]
    self.assertEquals(size, len(self.test4) )

    pass



if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


