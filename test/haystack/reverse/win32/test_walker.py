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
from haystack.reverse.win32 import win7heapwalker
from haystack.reverse.win32.win7heap import HEAP
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
    self._mappings = dump_loader.load('test/dumps/putty/putty.1.dump')

  def test_search(self):
    ''' def search(mappings, heap, filterInuse=False ):'''
    #self.skipTest('paused')

    known_heaps =[ 0x390000, 0x00540000, 0x005c0000, 0x1ef0000, 0x21f0000  ]

    found=[]
    for mapping in self._mappings:
      addr = mapping.start
      heap = mapping.readStruct( addr, HEAP )
      if addr in known_heaps:
        self.assertTrue(  heap.loadMembers(self._mappings, -1), "We expected a valid hit at @%x"%(addr) )
        found.append(addr)
      else:
        try:
          ret = heap.loadMembers(self._mappings, -1)
          self.assertFalse( ret, "We didnt expected a valid hit at @%x"%(addr) )
        except ValueError,e:
          self.assertRaisesRegexp( ValueError, 'error while loading members')
  
    found.sort()
    self.assertEquals( known_heaps, found)
  
    return  

  def test_getUserAllocations(self):
    ''' def getUserAllocations(mappings, heap, filterInuse=False):'''
    
    self.skipTest('paused')
    
    heaps = [ 0x390000, 0x00540000, 0x005c0000, 0x1ef0000, 0x21f0000  ]
    sizes = [ 8956, 868, 1704080, 604, 18762]
    ## TODO change for self._mappings.getHeaps()
    for addr, size in zip(heaps, sizes):
      m = self._mappings.getMmapForAddr(addr)
      #
      total = 0
      for chunk_addr, chunk_size in win7heapwalker.getUserAllocations(self._mappings, m, False):
        self.assertTrue( chunk_addr in self._mappings)
        total+=chunk_size
      
      self.assertEquals( total, size )
    
    return  



if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
