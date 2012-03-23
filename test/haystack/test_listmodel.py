#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.listmodel ."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack.config import Config
from haystack import model
from haystack import utils
from haystack.reverse.win32 import win7heap


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"



class TestListStruct(unittest.TestCase):
  '''
  haystack --dumpname putty.1.dump --string haystack.reverse.win32.win7heap.HEAP refresh 0x390000
  '''

  def setUp(self):
    self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
  
  def test_iter(self):
    #offset = 0x390000
    offset = 0x1ef0000
    self.m = self.mappings.getMmapForAddr(offset)
    self.heap = self.m.readStruct(offset, win7heap.HEAP)

    self.assertTrue(self.heap.loadMembers(self.mappings, 10 ))

    segments = [segment for segment in self.heap.iterateListField(self.mappings, 'SegmentList')]
    self.assertEquals( len(segments), 1)
    
    ucrs = [ucr for ucr in segment.iterateListField(self.mappings, 'UCRSegmentList') for segment in segments]
    self.assertEquals( len(ucrs), 1)
        
    logging.getLogger('root').debug('VIRTUAL')
    allocated = [ block for block in self.heap.iterateListField(self.mappings, 'VirtualAllocdBlocks') ]
    self.assertEquals( len(allocated), 0) # 'No vallocated blocks'

    for block in self.heap.iterateListField(self.mappings, 'VirtualAllocdBlocks') :
      print 'commit %x reserve %x'%(block.CommitSize, block.ReserveSize)
    

    return 

  def test_getListFieldInfo(self):
    
    heap = win7heap.HEAP()
    self.assertEquals(heap._getListFieldInfo('SegmentList'), (win7heap._HEAP_SEGMENT,-16))
    
    seg = win7heap._HEAP_SEGMENT()
    self.assertEquals(seg._getListFieldInfo('UCRSegmentList'), (win7heap._HEAP_UCR_DESCRIPTOR,-8))
    
  def test_otherHeap(self):
    #self.skipTest('not ready')
    
    heaps =[ 0x390000, 0x00540000, 0x005c0000, 0x1ef0000, 0x21f0000  ]
    for addr in heaps:
      print '\n+ Heap @%x'%(addr)
      m = self.mappings.getMmapForAddr(addr)
      heap = m.readStruct(addr, win7heap.HEAP)
      self.assertTrue(heap.loadMembers(self.mappings, 10 ))
      segments = [segment for segment in heap.iterateListField(self.mappings, 'SegmentList')]
      self.assertEquals( len(segments), 1)

      allocated = [ block for block in heap.iterateListField(self.mappings, 'VirtualAllocdBlocks') ]
      if len(allocated) == 0:
        print '+ NO vallocated blocks'
      else:
        print '+ vallocated blocks'
        for block in self.heap.iterateListField(self.mappings, 'VirtualAllocdBlocks') :
          print '\t- vallocated commit %x reserve %x'%(block.CommitSize, block.ReserveSize)
      
      #first = None
      chunks = [ chunk for chunk in heap.getChunks(self.mappings)]
      allocsize = sum( [c[1] for c in chunks ])
      print '+ %d chunks , for %d bytes'%( len(chunks), allocsize )
      
      for c in heap.getFrontendChunks(self.mappings):
        pass

class TestListStructTest5:#(unittest.TestCase):
  '''
  haystack --dumpname putty.1.dump --string haystack.reverse.win32.win7heap.HEAP refresh 0x390000
  '''

  def setUp(self):
    offset = 0x08f75008
    self.mappings = dump_loader.load('test/src/test-ctypes5.dump')
    sys.path.append('test/src/')
    import ctypes5
    self.m = self.mappings.getMmapForAddr(offset)
    self.usual = self.m.readStruct(offset, ctypes5.usual)
  
  def test_iter(self):
    
    self.assertTrue(self.usual.loadMembers(self.mappings, 10 ))
        
    nodes_addrs = [el for el in self.usual.root._iterateList(self.mappings)]

    self.assertEquals( len(nodes_addrs), 2)

    return 




if __name__ == '__main__':
  #logging.getLogger("listmodel").setLevel(level=logging.DEBUG)  
  #logging.getLogger("root").setLevel(level=logging.DEBUG)  
  #logging.getLogger("win7heap").setLevel(level=logging.DEBUG)  
  #logging.getLogger("dump_loader").setLevel(level=logging.INFO)  
  #logging.getLogger("memory_mapping").setLevel(level=logging.INFO)  
  logging.basicConfig(level=logging.INFO)  
  unittest.main(verbosity=2)

