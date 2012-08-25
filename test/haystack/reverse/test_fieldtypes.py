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

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

class TestField(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = None #reversers.getContext('test/src/test-ctypes3.dump')

  def setUp(self):  
    pass

  def tearDown(self):
    pass

  def test_init(self):
    # struct_682638 in putty.7124.dump
    vaddr = 0x682638
    size = 184
    ctx = reversers.getContext('test/dumps/putty/putty.7124.dump')
    st = structure.makeStructure(ctx, vaddr, size)
    # try it
    offset = 12
    #me = Field(st, offset, typename, size, isPadding)
    
    st.decodeFields()
    print st.toString()
    fields = st.getFields()
    
    self.assertEquals( len(fields), 6)
    
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRING)
    #  print f
    
    pass



if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


