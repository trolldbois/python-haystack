#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import os
import unittest
import logging
import tempfile
import time
import mmap

from haystack import memory_mapping, utils
from haystack.config import Config
from haystack.reverse import reversers

class TestMmapHack(unittest.TestCase):
  def test_mmap_hack(self):
    fname = os.path.normpath(os.path.abspath(__file__))
    fin = file(fname)
    local_mmap_bytebuffer = mmap.mmap(fin.fileno(), 1024, access=mmap.ACCESS_READ)
    fin.close()
    fin = None
    # yeap, that right, I'm stealing the pointer value. DEAL WITH IT.
    heapmap = utils.unpackWord((Config.WORDTYPE).from_address(id(local_mmap_bytebuffer) + 2*Config.WORDSIZE ) )
    print 'MMAP HACK: heapmap: 0x%0.8x'%(heapmap)
    class P:
      pid=os.getpid()
    maps = memory_mapping.readProcessMappings(P()) # memory_mapping
    #print '\n'.join([str(m) for m in maps])
    ret=[m for m in maps if heapmap in m]
    self.assertEquals( len(ret), 1)
    self.assertEquals( ret[0].pathname, fname)


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
    self.ssh.reset()
    self.putty.reset()
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
    #print ''.join(['%s\n'%(m) for m in mappings])    
    with self.assertRaises(ValueError):
      mappings.get_context(0x0)
    with self.assertRaises(ValueError):
      mappings.get_context(0xb76e12d3)
    #[heap] children
    self.assertEquals(mappings.get_context(0x0062d000).heap, mappings.getMmapForAddr(0x005c0000))
    self.assertEquals(mappings.get_context(0x0063e123).heap, mappings.getMmapForAddr(0x005c0000))

  
  def test_get_user_allocations(self):
    mappings = self.ssh.mappings
    allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
    self.assertEquals( len(allocs), 2568)

    mappings = self.putty.mappings
    allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
    self.assertEquals( len(allocs), 2273)

  def test_getMmap(self):
    mappings = self.ssh.mappings
    self.assertEquals( len(mappings.getMmap('[heap]')), 1)
    self.assertEquals( len(mappings.getMmap('None')), 9)
    #really
    mappings = self.putty.mappings
    with self.assertRaises(IndexError):
      self.assertEquals( len(mappings.getMmap('[heap]')), 1)
    self.assertEquals( len(mappings.getMmap('None')), 71)

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

  @unittest.expectedFailure # FIXME
  def test_getStack(self):
    mappings = self.ssh.mappings
    #print ''.join(['%s\n'%(m) for m in mappings])    
    self.assertEquals( mappings.getStack().start, 0xbff45000)
    self.assertEquals( mappings.getStack().pathname, '[stack]')
    #TODO win32    
    mappings = self.putty.mappings
    #print ''.join(['%s\n'%(m) for m in mappings])    
    #print mappings.getStack() # no [stack]
    self.assertEquals( mappings.getStack().start, 0x00400000)
    self.assertEquals( mappings.getStack().pathname, '''C:\Program Files (x86)\PuTTY\putty.exe''')
    
  def test_contains(self):
    mappings = self.ssh.mappings
    for m in mappings:
      self.assertTrue( m.start in mappings)
      self.assertTrue( (m.end-1) in mappings)
    
    mappings = self.putty.mappings
    for m in mappings:
      self.assertTrue( m.start in mappings)
      self.assertTrue( (m.end-1) in mappings)

  def test_len(self):
    mappings = self.ssh.mappings
    self.assertEquals( len(mappings), 70)
    mappings = self.putty.mappings
    self.assertEquals( len(mappings), 403)
    
  def test_getitem(self):
    mappings = self.ssh.mappings
    self.assertTrue( isinstance(mappings[0], memory_mapping.MemoryMapping))
    self.assertTrue( isinstance(mappings[len(mappings)-1], memory_mapping.MemoryMapping))
    with self.assertRaises(IndexError):
      mappings[0x0005c000]
    mappings = self.putty.mappings
    self.assertTrue( isinstance(mappings[0], memory_mapping.MemoryMapping))
    self.assertTrue( isinstance(mappings[len(mappings)-1], memory_mapping.MemoryMapping))
    with self.assertRaises(IndexError):
      mappings[0x0005c000]
    
  def test_iter(self):
    mappings = self.ssh.mappings
    mps = [m for m in mappings]
    mps2 = [m for m in mappings.mappings]
    self.assertEquals(mps, mps2)
    
    mappings = self.putty.mappings
    mps = [m for m in mappings]
    mps2 = [m for m in mappings.mappings]
    self.assertEquals(mps, mps2)

  def test_setitem(self):
    mappings = self.ssh.mappings
    with self.assertRaises(NotImplementedError):
      mappings[0x0005c000] = 1
    
    mappings = self.putty.mappings
    with self.assertRaises(NotImplementedError):
      mappings[0x0005c000]=1

  def test_search_win_heaps(self):
    self.skipTest('')
  
  def test_get_target_system(self):
    self.skipTest('')
  
  def test_get_mmap_for_haystack_addr(self):
    self.skipTest('')
    
  
 

if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
  logging.getLogger('basicmodel').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('listmodel').setLevel(logging.INFO)
  unittest.main(verbosity=2)


