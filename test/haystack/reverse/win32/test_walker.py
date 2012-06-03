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

log = logging.getLogger('testwalker')

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

  def test_sortedHeaps(self):
    ''' check if memory_mapping has sorted heap by index. '''
    self.skipTest('paused')
    
    for i, m in enumerate(self._mappings.getHeaps()):
      #print '%d @%0.8x'%(win7heapwalker.readHeap(self._mappings, m).ProcessHeapsListIndex, m.start)
      self.assertEquals(win7heapwalker.readHeap(self._mappings, m).ProcessHeapsListIndex, i+1, 'ProcesHeaps should have correct indexes')
    return

  def test_isHeap(self):
    ''' check if the isHeap fn perform correctly.'''
    self.skipTest('paused')

    self.assertEquals( self._mappings.get_target_system(), 'win32')
        
    for m in self._mappings.getHeaps():
      gen = self._mappings.getUserAllocations(self._mappings, m)
      try:
        for addr,s in gen:
          #print '(0x%x,0x%x)'%(addr,s) 
          pass
        log.debug('0x%x is heap'%(m.start))
      except ValueError,e:
        log.debug('0x%x is not heap'%(m.start))
    return  

  def test_totalsize(self):
    ''' check if there is an adequate allocation rate as per getUserAllocations '''
    
    self.assertEquals( self._mappings.get_target_system(), 'win32')
    
    allocs=list()
    for m in self._mappings.getHeaps():
      gen = self._mappings.getUserAllocations(self._mappings, m)
      allocs.extend( [(addr,s) for addr,s in gen])
    
    self.assertEquals( len(allocs), len(set(allocs)) , 'duplicates allocs found')
    
    addrs = [addr for addr,s in allocs]
    self.assertEquals( len(addrs), len(set(addrs)) , 'duplicates allocs found but different sizes')

    where = dict()
    for addr,s in allocs:
      m = self._mappings.getMmapForAddr(addr)
      if addr+s > m.end:
        log.debug('OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x'%(m.start,m.end, addr, s, addr+s) )
      if m in where:
        where[m].append( (addr,s) )
      else:
        where[m] = [ (addr,s) ]
    # calculate allocated size
    for m,allocs in where.items():
      totalsize = sum([s for addr,s in allocs])
      log.info('@%0.8x size: %d allocated: %d = %0.2f %%'%(m.start,len(m), totalsize, 100*totalsize/len(m)) )
      allocs.sort()
      lastend = 0
      lasts = 0
      addsize =0
      for addr,s in allocs:
        if addr < lastend :
          #log.debug('0x%0.8x (%d) last:0x%0.8x-0x%0.8x (%d) new:0x%0.8x-0x%0.8x (%d)'%(m.start, 
          #                  len(m), lastend-lasts,lastend,lasts, addr, addr+s, s) )
          addsize+=s
        else: # keep last big chunk on the stack before moving to next one.
          if addsize != 0:
            #log.debug('previous fth_chunks cumulated to %d lasts:%d'%(addsize, lasts))
            addsize = 0
          lastend = addr+s
          lasts = s
    # so chunks are englobing fth_chunks
    # _heap.ProcessHeapsListIndex give the order of heaps....
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
  logging.basicConfig(level=logging.INFO)
  #logging.getLogger('testwalker').setLevel(level=logging.DEBUG)
  #logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
  #logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
  logging.getLogger('dump_loader').setLevel(level=logging.INFO)
  logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
  unittest.main(verbosity=4)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
