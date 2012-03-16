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
from haystack.reverse.win32 import ctypes_alloc
from haystack import dump_loader

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

class TestAllocator(unittest.TestCase):

  def setUp(self):  
    self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')

  def test_search(self):
    ''' def search(mappings, heap, filterInuse=False ):'''
    #self.skipTest('notready')
    from haystack import dump_loader
    from haystack.reverse.win32.win7heap import HEAP

    maps=[m for m in self.mappings   if m.permissions == 'rw-' ]
    for m in maps:
      if m.permissions == 'rw-':
        heap = m.readStruct( m.start, HEAP )
        print heap.toString()
  
  
    return  

  def test_getUserAllocations(self):
    ''' def getUserAllocations(mappings, heap, filterInuse=False):'''
    self.skipTest('notready')
       
    # we need mappings from 
    for mapping in self.mappings:
      try:
        if mapping.pathname == 'None':
          if ctypes_alloc.isMallocHeap(self.mappings, mapping):
            allocs = [a for a in ctypes_alloc.getUserAllocations(self.mappings, mapping)]
            print '%d alloc blocks'%(len(allocs))
      except ValueError,e:
        pass    
    
    self.assertTrue(True)
    
    return  

  def test_isMallocHeap(self):
    ''' def isMallocHeap(mappings, mapping):'''
    self.skipTest('notready')

    # we need mappings from 
    for mapping in self.mappings:
      try:
        if mapping.pathname == 'None':
          print mapping, ctypes_alloc.isMallocHeap(self.mappings, mapping)
          pass
        if ctypes_alloc.isMallocHeap(self.mappings, mapping):
          print '8********** TRUE', len(mapping), mapping
      except ValueError,e:
        pass    
    self.assertTrue(True)
    return  


if __name__ == '__main__':
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
