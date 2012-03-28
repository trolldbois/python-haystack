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
from haystack.reverse.libc import ctypes_malloc as ctypes_alloc
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
    self.mappings = dump_loader.load('test/dumps/ssh/ssh.1')

  def test_search(self):
    ''' def search(mappings, heap, filterInuse=False ):'''
    self.skipTest('notready')
    return  

  def test_getUserAllocations(self):
    ''' List all user allocations.'''
    #self.skipTest('notready')
       
    # we need mappings from 
    for mapping in self.mappings:
      try:
        if ctypes_alloc.isMallocHeap(self.mappings, mapping):
          allocs = [a for a in ctypes_alloc.getUserAllocations(self.mappings, mapping)]
          print '%d alloc blocks for %d bytes/%d'%(len(allocs), sum( [size for addr,size in allocs ]), len(mapping))
      except ValueError,e:
        pass    
    
    self.assertTrue(True)
    
    return  

  def test_isMallocHeap(self):
    ''' test if a mpaping is a heap'''
    #self.skipTest('notready')

    # we need mappings from 
    for mapping in self.mappings:
      try:
        if ctypes_alloc.isMallocHeap(self.mappings, mapping):
          print '8********** TRUE', len(mapping), mapping
      except ValueError,e:
        pass    
    self.assertTrue(True)
    return  


if __name__ == '__main__':
  unittest.main(verbosity=3)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
