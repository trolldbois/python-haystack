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
    offset = 0x390000
    self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
    self.m = self.mappings.getMmapForAddr(offset)
    self.heap = self.m.readStruct(offset, win7heap.HEAP)
  
  def test_iter(self):

    self.assertTrue(self.heap.loadMembers(self.mappings, 10 ))

    segments = [segment for segment in self.heap.iterateListField(self.mappings, 'SegmentList')]
    self.assertEquals( len(segments), 1)
    
    ucrs = [ucr for ucr in segment.iterateListField(self.mappings, 'UCRSegmentList') for segment in segments]
    self.assertEquals( len(ucrs), 1)

    for segment in segments:
      skiplist = []
      for ucr in segment.iterateListField(self.mappings, 'UCRSegmentList'):
        skiplist.append( (ucr.Address, ucr.Size) )
        print "a:%x, s:%x"%(ucr.Address, ucr.Size)
        
      print segment
        

    for el in self.heap.UCRList._iterateList(self.mappings):
      print el

    return 

  def test_getListFieldInfo(self):
    
    heap = win7heap.HEAP()
    self.assertEquals(heap._getListFieldInfo('SegmentList'), (win7heap._HEAP_SEGMENT,-16))
    
    seg = win7heap._HEAP_SEGMENT()
    self.assertEquals(seg._getListFieldInfo('UCRSegmentList'), (win7heap._HEAP_UCR_DESCRIPTOR,-8))
    
  def test_otherHeap(self):
    heaps =[  0x00540000, 0x005c0000, 0x1ef0000, 0x21f0000  ]
    for addr in heaps:
      m = self.mappings.getMmapForAddr(addr)
      heap = self.m.readStruct(addr, win7heap.HEAP)
      self.assertTrue(heap.loadMembers(self.mappings, 10 ))
      print heap
    

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
  #logging.getLogger("dump_loader").setLevel(level=logging.INFO)  
  #logging.getLogger("memory_mapping").setLevel(level=logging.INFO)  
  #logging.basicConfig(level=logging.INFO)  
  unittest.main(verbosity=2)

