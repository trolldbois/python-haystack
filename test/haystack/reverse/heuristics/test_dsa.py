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
from haystack.reverse import fieldtypes, structure, reversers
from haystack.reverse.fieldtypes import FieldType
from haystack.reverse.heuristics.dsa import *

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

log = logging.getLogger('test_field_analyser')

class TestFieldAnalyser(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.test1 = FS('''\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00....''')
    self.test2 = FS('''....\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00''')
    self.test3 = FS('''....1234aaaa.....''')
    self.test4 = FS('''\x00\x00\x00\x00h\x00i\x00 \x00m\x00y\x00 \x00n\x00a\x00m\x00e\x00\x00\x00\xef\x00\x00\x00\x00\x00....''')
    self.test5 = FS('\xd8\xf2d\x00P\xf3d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00CryptDllVerifyEncodedSignature\x00\x00')
    self.test6 = FS('''edrtfguyiopserdtyuhijo45567890oguiy4e65rtiu\xf1\x07\x08\x09\x00''')
    #
    self.test8 = FS('C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00D\x00r\x00i\x00v\x00e\x00r\x00S\x00t\x00o\x00r\x00e\x00\x00\x00\xf1/\xa6\x08\x00\x00\x00\x88,\x00\x00\x00C\x00:\x00\\\x00P\x00r\x00o\x00g\x00r\x00a\x00m\x00 \x00F\x00i\x00l\x00e\x00s\x00 \x00(\x00x\x008\x006\x00)\x00\x00\x00P\x00u\x00T\x00Y\x00')
    self.zeroes = ZeroFields()
    self.utf16 = UTF16Fields()
    self.ascii = PrintableAsciiFields()
    self.ints = IntegerFields()
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

    fields = self.zeroes.make_fields(self.test2, 0, len(self.test2))
    self.assertEquals( len(fields) , 3)
    self.assertEquals( fields[0].offset , 4)
    self.assertEquals( fields[0].size , 4)
    self.assertEquals( fields[1].offset , 12)
    self.assertEquals( fields[1].size , 8)
    self.assertEquals( fields[2].offset , 32)
    self.assertEquals( fields[2].size , 4)
    
    fields = self.zeroes.make_fields(self.test3, 0, len(self.test3))
    self.assertEquals( len(fields) , 0)

    fields = self.zeroes.make_fields(self.test4, 0, len(self.test4))
    self.assertEquals( len(fields) , 2)

    with self.assertRaises(AssertionError): # unaligned offset
      fields = self.zeroes.make_fields(self.test4, 1, len(self.test4))

    fields = self.zeroes.make_fields(self.test4, 4, len(self.test4))
    self.assertEquals( len(fields) , 1)

    fields = self.zeroes.make_fields(self.test5, 0, len(self.test5))
    self.assertEquals( len(fields) , 1)


  def test_utf16(self):
    fields = self.utf16.make_fields(self.test1, 0, len(self.test1))
    self.assertEquals(len(fields), 0) # no utf16

    fields = self.utf16.make_fields(self.test8, 0, len(self.test8))
    self.assertEquals(len(fields), 3) # 3 utf-16
    
    fields = self.utf16.make_fields(self.test6, 0, len(self.test6))
    self.assertEquals(len(fields), 0) 

  def test_small_int(self):
    ''' we default to WORDSIZE == 4 '''
    smallints = [  '\xff\xff\xff\xff', '\x02\xff\xff\xff',  ]
    for bytes in smallints:
      fields = self.ints.make_fields( FS(bytes), 0, 4 )
      self.assertEquals( len(fields), 1)
      self.assertEquals( fields[0].endianess , '<')

    smallints = [  '\xff\xff\xff\x03', '\x00\x00\x00\x42',
                   '\x00\x00\x00\x01', '\x00\x00\x01\xaa', ]
    for bytes in smallints:
      fields = self.ints.make_fields( FS(bytes), 0, 4 )
      self.assertEquals( len(fields), 1, repr(bytes))
      self.assertEquals( fields[0].endianess , '>')

    not_smallints = [  '\xfa\xff\xfb\xff', '\x01\xff\xff\x03', '\x02\xff\x42\xff', 
                   '\x01\x00\x00\x01', '\x00\x12\x01\xaa', '\x00\xad\x00\x42', 
                   '\x00\x41\x00\x41', '\x41\x00\x41\x00']
    for bytes in not_smallints:
      fields = self.ints.make_fields( FS(bytes), 0, 4 )
      self.assertEquals( len(fields), 0)
    

class TestDSA(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = None #reversers.getContext('test/src/test-ctypes3.dump')
    self.putty7124 = reversers.getContext('test/dumps/putty/putty.7124.dump')
    self.dsa = DSASimple()
    
  def setUp(self):  
    pass

  def tearDown(self):
    pass
  
  @unittest.expectedFailure #'utf16 should start on aligned byte'
  def test_utf_16_le_null_terminated(self):

    # struct_682638 in putty.7124.dump
    vaddr = 0x682638
    size = 184
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 5) # TODO should be 6 fields lllttp
    self.assertEquals( fields[2].typename, fieldtypes.FieldType.STRING16)
    self.assertTrue( fields[2].isString())
    # TODO fields[3] should start at offset 12, not 10.
    self.assertEquals( fields[3].typename, fieldtypes.FieldType.STRING16)
    self.assertTrue( fields[3].isString())
    #  print f
    
  def test_utf_16_le_non_null_terminated(self):
    ''' non-null terminated '''
    # struct_691ed8 in putty.7124.dump
    vaddr = 0x691ed8
    size = 256
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 2)
    self.assertEquals( fields[1].typename, fieldtypes.FieldType.STRING16)
    self.assertTrue( fields[1].isString())


  def test_ascii_null_terminated_2(self):
    ''' null terminated '''
    # struct_64f328 in putty.7124.dump
    vaddr = 0x64f328
    size = 72
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
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
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 2) # should be 3 Lt0?
    self.assertEquals( fields[0].typename, fieldtypes.FieldType.STRING16)
    self.assertTrue( fields[0].isString())

  def test_big_block(self):
    ''' null terminated '''
    # in putty.7124.dump
    vaddr = 0x63d4c8 #+ 1968
    size = 4088 #128
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertLess( len(fields), 879)
    #self.assertEquals( fields[35].typename, fieldtypes.FieldType.STRINGNULL)
    #self.assertTrue( fields[35].isString())
    strfields = [f for f in st.getFields() if f.isString()]
    #for f in strfields:
    #  print f.toString(),
    self.assertGreater( len(strfields), 30 )

  def test_uuid(self):
    ''' null terminated '''
    # in putty.7124.dump
    vaddr = 0x63aa68
    size = 120
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertEquals( len(fields), 3)
    self.assertEquals( fields[1].typename, fieldtypes.FieldType.STRING16)
    self.assertTrue( fields[1].isString())

    pass

  def test_big_block_2(self):
    # in putty.7124.dump
    vaddr = 0x675b30
    size = 8184
    st = structure.makeStructure(self.putty7124, vaddr, size)    
    self.dsa.analyze_fields(st)
    #print repr(st.bytes)
    log.debug(st.toString())
    fields = st.getFields()
    self.assertLess( len(fields), 879)
    #self.assertEquals( fields[35].typename, fieldtypes.FieldType.STRINGNULL)
    #self.assertTrue( fields[35].isString())
    fields = [f for f in st.getFields() if f.isString()]
    #for f in fields:
    #  print f.toString(),


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
  logging.getLogger('test_field_analyser').setLevel(level=logging.DEBUG)
  logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
  logging.getLogger("structure").setLevel(level=logging.DEBUG)
  logging.getLogger("field").setLevel(level=logging.DEBUG)
  #logging.getLogger("dsa").setLevel(level=logging.DEBUG)
  logging.getLogger("re_string").setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)


