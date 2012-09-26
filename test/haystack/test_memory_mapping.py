#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import os
import unittest
import logging
import tempfile
import time

from haystack import memory_mapping
from haystack.reverse import reversers


class TestMappings(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.context = reversers.getContext('test/src/test-ctypes3.dump')
    self.ssh = reversers.getContext('test/dumps/ssh/ssh.1')
    self.putty = reversers.getContext('test/dumps/putty/putty.1.dump')
    pass

  def setUp(self):  
    pass

  def tearDown(self):
    #self.context = None
    self.context.reset()      
    pass

  def test_get_context(self):
    mappings = self.ssh.mappings
    #print ''.join(['%s\n'%(m) for m in mappings])    
    with self.assertRaises(ValueError):
      mappings.get_context(0x0)
    with self.assertRaises(ValueError):
      mappings.get_context(0xb76e12d3)
    #[heap]
    self.assertEquals(mappings.get_context(0xb84e02d3).heap, mappings.getMmapForAddr(0xb84e02d3))

    mappings = self.putty.mappings
    print ''.join(['%s\n'%(m) for m in mappings])    
    with self.assertRaises(ValueError):
      mappings.get_context(0x0)
    with self.assertRaises(ValueError):
      mappings.get_context(0xb76e12d3)
    #[heap] children
    self.assertEquals(mappings.get_context(0x0062d000).heap, mappings.getMmapForAddr(0x005c0000))
    self.assertEquals(mappings.get_context(0x0063e123).heap, mappings.getMmapForAddr(0x005c0000))

  
  def test_get_user_allocations(self):
    self.skipTest('')

  def test_getMmap(self):
    self.skipTest('')

  def test_getMmapForAddr(self):
    mappings = self.ssh.mappings
    self.assertEquals(mappings.getHeap(), mappings.getMmapForAddr(0xb84e02d3))

  def test_getHeap(self):
    mappings = self.ssh.mappings
    self.assertTrue( isinstance(mappings.getHeap(), memory_mapping.MemoryMapping))
    self.assertEquals( mappings.getHeap().start, 0xb84e0000)
    self.assertEquals( mappings.getHeap().pathname, '[heap]')
    #really
    mappings = self.putty.mappings
    self.assertTrue( isinstance(mappings.getHeap(), memory_mapping.MemoryMapping))
    self.assertEquals( mappings.getHeap().start, 0x005c0000)
    self.assertEquals( mappings.getHeap().pathname, 'None')

  def test_getHeaps(self):
    mappings = self.ssh.mappings
    self.assertEquals( len(mappings.getHeaps()), 1) # really ?
    mappings = self.putty.mappings
    self.assertEquals( len(mappings.getHeaps()), 12)

  def test_getStack(self):
    self.skipTest('')

  def test_search_win_heaps(self):
    self.skipTest('')
  
  def test_get_target_system(self):
    self.skipTest('')
  
  def test_get_mmap_for_haystack_addr(self):
    self.skipTest('')
    
  def test_contains(self):
    self.skipTest('')

  def test_len(self):
    self.skipTest('')
  def test_getitem(self):
    self.skipTest('')
  def test_setitem(self):
    self.skipTest('')
  def test_iter(self):
    self.skipTest('')
  
 

if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
  logging.getLogger('basicmodel').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('listmodel').setLevel(logging.INFO)
  unittest.main(verbosity=2)


