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

  def a_test_utf_16_le_null_terminated(self):
    ctx = reversers.getContext('test/dumps/putty/putty.7124.dump')

    # struct_682638 in putty.7124.dump
    vaddr = 0x682638
    size = 184
    st = structure.makeStructure(ctx, vaddr, size)    
    st.decodeFields()
    #print st.toString()
    fields = st.getFields()
    self.assertEquals( len(fields), 6)
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRINGNULL)
    self.assertTrue( fields[3].isString())
    #  print f
    
  def a_test_utf_16_le_non_null_terminated(self):
    ''' non-null terminated '''
    ctx = reversers.getContext('test/dumps/putty/putty.7124.dump')
    # struct_691ed8 in putty.7124.dump
    vaddr = 0x691ed8
    size = 256
    st = structure.makeStructure(ctx, vaddr, size)    
    st.decodeFields()
    #print st.toString()
    fields = st.getFields()
    self.assertEquals( len(fields), 2)
    self.assertEquals( fields[1].typename, fieldtypes.FieldType.STRING)
    self.assertTrue( fields[1].isString())

    # TODO, check 0x63aa68 also
    # txt field should start at [2:] , but is crunched by fake pointer value
    pass

  def test_utf_16_le_null_terminated_2(self):
    ''' null terminated '''
    ctx = reversers.getContext('test/dumps/putty/putty.7124.dump')
    # struct_64f328 in putty.7124.dump
    vaddr = 0x64f328
    size = 72
    st = structure.makeStructure(ctx, vaddr, size)    
    st.decodeFields()
    print st.toString()
    fields = st.getFields()
    self.assertEquals( len(fields), 2)
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRINGNULL)
    self.assertTrue( fields[3].isString())

    # TODO, check 0x63aa68 also
    # txt field should start at [2:] , but is crunched by fake pointer value
    pass


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


