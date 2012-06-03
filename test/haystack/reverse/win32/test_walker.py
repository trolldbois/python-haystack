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
    self._known_heaps = [ (0x00390000, 8956), (0x00540000, 868),
                    ( 0x00580000, 111933), (0x005c0000, 1704080) , 
                    ( 0x01ef0000, 604), (0x02010000, 61348), 
                    ( 0x02080000, 474949), (0x021f0000 , 18762),
                    ( 0x03360000, 604), (0x04030000 , 632),
                    ( 0x04110000, 1334), (0x041c0000 , 644),
                    ]

  def tearDown(self):
    from haystack import model 
    model.reset()

  def test_isHeap(self):
    #self.skipTest('paused')
    
    for m in self._mappings.getHeaps():
      gen = self._mappings.getUserAllocations(self._mappings, m)
      try:
        for addr,s in gen:
          print '(0x%x,0x%x)'%(addr,s) 
        print('0x%x is heap'%(m.start))
      except ValueError,e:
        print('0x%x is not heap'%(m.start))
    return  

  def test_search(self):
    '''  Testing the loading of _HEAP in each memory mapping. Compare loadMembers results with known offsets. expect failures otherwise. '''
    self.skipTest('paused')
    
    found=[]
    for mapping in self._mappings:
      addr = mapping.start
      heap = mapping.readStruct( addr, HEAP )
      if addr in map(lambda x:x[0] , self._known_heaps):
        self.assertTrue(  heap.loadMembers(self._mappings, -1), "We expected a valid hit at @%x"%(addr) )
        found.append(addr, )
      else:
        try:
          ret = heap.loadMembers(self._mappings, -1)
          self.assertFalse( ret, "We didnt expected a valid hit at @%x"%(addr) )
        except ValueError,e:
          self.assertRaisesRegexp( ValueError, 'error while loading members')
  
    found.sort()
    self.assertEquals( map(lambda x:x[0] , self._known_heaps), found)
  
    return  

  def test_getUserAllocations(self):
    ''' For each known _HEAP, load all user Allocation and compare the number of allocated bytes. '''
    
    self.skipTest('paused')
    
    ## TODO change for self._mappings.getHeaps()
    for addr, size in self._known_heaps:
      m = self._mappings.getMmapForAddr(addr)
      #
      total = 0
      for chunk_addr, chunk_size in win7heapwalker.getUserAllocations(self._mappings, m, False):
        self.assertTrue( chunk_addr in self._mappings)
        total+=chunk_size
      
      self.assertEquals( total, size )
    
    return  



if __name__ == '__main__':
  #logging.basicConfig(level=logging.DEBUG)
  #logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
  #logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
  #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
  #logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
  unittest.main(verbosity=4)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
