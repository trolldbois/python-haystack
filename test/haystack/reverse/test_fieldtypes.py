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

log = logging.getLogger('test_fieldtypes')

class TestField(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = None #reversers.getContext('test/src/test-ctypes3.dump')
    self.putty7124 = reversers.getContext('test/dumps/putty/putty.7124.dump')

  def setUp(self):  
    pass

  def tearDown(self):
    pass

  def test_utf_16_le_null_terminated(self):

    # struct_682638 in putty.7124.dump
    vaddr = 0x682638
    size = 184
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 5)
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRINGNULL)
    self.assertTrue( fields[3].isString())
    #  print f
    
  def test_utf_16_le_non_null_terminated(self):
    ''' non-null terminated '''
    # struct_691ed8 in putty.7124.dump
    vaddr = 0x691ed8
    size = 256
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 2)
    self.assertEquals( fields[1].typename, fieldtypes.FieldType.STRING)
    self.assertTrue( fields[1].isString())


  def test_utf_16_le_null_terminated_2(self):
    ''' null terminated '''
    # struct_64f328 in putty.7124.dump
    vaddr = 0x64f328
    size = 72
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 5)
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRINGNULL)
    self.assertTrue( fields[3].isString())

  def test_utf_16_le_null_terminated_3(self):
    ''' null terminated '''
    # in putty.7124.dump
    vaddr = 0x657488
    size = 88
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 2)
    self.assertEquals( fields[0].typename, fieldtypes.FieldType.STRING)
    self.assertTrue( fields[0].isString())

  def test_big_block(self):
    ''' null terminated '''
    # in putty.7124.dump
    vaddr = 0x63d4c8 #+ 1968
    size = 4088 #128
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertLess( len(fields), 879)
    #self.assertEquals( fields[35].typename, fieldtypes.FieldType.STRINGNULL)
    #self.assertTrue( fields[35].isString())

  def test_uuid(self):
    ''' null terminated '''
    # in putty.7124.dump
    vaddr = 0x63aa68
    size = 120
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    st.decodeFields()
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 3)
    self.assertEquals( fields[2].typename, fieldtypes.FieldType.STRINGNULL)
    self.assertTrue( fields[2].isString())

    # TODO, check 0x63aa68 also
    # txt field should start at [2:] , but is crunched by fake pointer value
    pass


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


