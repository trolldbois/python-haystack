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
from haystack.reverse import structure
from haystack.reverse import reversers

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger("test_structure")
import ctypes 

class TestStructure(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = reversers.getContext('test/src/test-ctypes3.dump')
    #context.reset()      

  def setUp(self):  
    #self.context = reversers.getContext('test/src/test-ctypes3.dump')
    pass

  def tearDown(self):
    #self.context = None
    pass

  def test_init(self):
    for s in self.context.listStructures():
      if len(s) == 12 : #Node + padding, 1 pointer on create
        self.assertEqual( len(s.getFields()), len(s.getPointerFields()))
      elif len(s) == 20 : #test3, 1 pointer on create
        self.assertEqual( len(s.getFields()), len(s.getPointerFields()))
    return  

  def test_decodeFields(self):
    for s in self.context.listStructures():
      s.decodeFields()
      if len(s) == 12 : #Node + padding, 1 pointer on create
        self.assertEqual( len(s.getFields()), 3 ) # 1, 2 and padding
        self.assertEqual( len(s.getPointerFields()), 1)
      elif len(s) == 20 : #test3, 1 pointer on create
        # fields, no heuristic to detect medium sized int
        # TODO untyped of size < 8 == int * x
        print s.toString()
        self.assertEqual( len(s.getFields()), 3 )
        self.assertEqual( len(s.getPointerFields()), 1)
    return  

  def test_resolvePointers(self):
    for s in self.context.listStructures():
      s.resolvePointers()
    self.assertTrue(True) # test no error

  def test_resolvePointers2(self):
    for s in self.context.listStructures():
      s.decodeFields()
      s.resolvePointers()
      if len(s) == 12 : #Node + padding, 1 pointer on create
        self.assertEqual( len(s.getFields()), 3 ) # 1, 2 and padding
        self.assertEqual( len(s.getPointerFields()), 1)
  
  def test_reset(self):
    for s in self.context.listStructures():
      s.reset()
      if isinstance(s, structure.CacheWrapper):
        members = s.obj().__dict__
      else:
        members = s.__dict__
      for name,value in members.items():
        if name in ['_size', '_context', '_name', '_vaddr']:
          self.assertNotIn( value, [None, False] )
        elif name in ['_dirty']:
          self.assertTrue( value )
        elif name in ['_fields']:
          self.assertEquals( value, list() )
        elif name in ['dumpname']:
          self.assertTrue( os.access(value,os.F_OK) )
        else:
          self.assertIn( value, [None, False], name+' not resetted' )


  def test_string_overlap(self):
    self.context = reversers.getContext('test/src/test-ctypes6.dump')
    for s in self.context.listStructures():
      #s.resolvePointers()
      s.decodeFields()
      log.debug(s.toString())
    self.assertTrue(True) # test no error




if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  logging.getLogger("test_structure").setLevel(logging.DEBUG)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
  unittest.main(verbosity=2)
  
  
  
