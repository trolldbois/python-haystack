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
from haystack.reverse import reversers
from haystack.reverse.libc import ctypes_malloc as ctypes_alloc
from haystack.reverse.libc import libcheapwalker
from haystack import dump_loader

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes 

class TestAllocator(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.ssh1 = reversers.getContext('test/dumps/ssh/ssh.1')

  @classmethod
  def tearDownClass(self):  
    from haystack import model
    model.reset()
    self.ssh1 = None
    return
    
  def test_search(self):
    ''' def search(mappings, heap, filterInuse=False ):'''
    self.skipTest('notready')
    return  

  def test_chunks_numbers(self):
    ''' Count all user allocations and free chunks'''
    #self.skipTest('notready')

    mappings = self.ssh1.mappings
    heaps = mappings.getHeaps()
    self.assertEquals(len(heaps), 1)
    
    heap = heaps[0]
    self.assertTrue(ctypes_alloc.is_malloc_heap(mappings, heap))

    walker = libcheapwalker.LibcHeapWalker(mappings, heap, 0)
    # we should have 3 structures + 1 empty chunks
    allocs = walker.get_user_allocations()
    self.assertEquals( len(allocs) , 2568 )
    size = sum([size for addr,size in allocs])
    self.assertEquals( size, 105616)
    
    # the empty chunk
    free = walker.get_free_chunks()
    self.assertEquals( len(free) , 7 )
    size = sum([size for addr,size in free])
    self.assertEquals( size, 19252)
       

    return  


class TestAllocatorSimple(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context6 = reversers.getContext('test/src/test-ctypes6.dump')

  @classmethod
  def tearDownClass(self):  
    from haystack import model
    model.reset()
    self.context6 = None
    return

  def test_ctypes6(self):
    mappings = self.context6.mappings
    heaps = mappings.getHeaps()
    self.assertEquals(len(heaps), 1)
    
    heap = heaps[0]
    self.assertTrue(ctypes_alloc.is_malloc_heap(mappings, heap))

    walker = libcheapwalker.LibcHeapWalker(mappings, heap, 0)
    # we should have 3 structures + 1 empty chunks
    allocs = walker.get_user_allocations()
    self.assertEquals( len(allocs) , 3 )
    
    # the empty chunk
    free = walker.get_free_chunks()
    self.assertEquals( len(free) , 1 )


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
  
  
  
