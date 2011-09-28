#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

from haystack import pattern
from haystack import memory_mapping

import struct
import operator
import os
import unittest


class Config:
  WORD_LENGTH = 4
  MMAP_START = 0x0c00000
  MMAP_STOP =  0x0c01000
  MMAP_LENGTH = 4096
  STRUCT_OFFSET = 44
  cacheDir = os.path.normpath('./outputs/')


def accumulate(iterable, func=operator.add):
  it = iter(iterable)
  total = next(it)
  yield total
  for element in it:
    total = func(total, element)
    yield total

def makeMMap( seq, start=Config.MMAP_START, offset=Config.STRUCT_OFFSET  ):
  nsig = [offset]
  nsig.extend(seq)
  indices = [ i for i in accumulate(nsig)]
  dump = [] #b''
  for i in range(0,Config.MMAP_LENGTH, Config.WORD_LENGTH): 
    if i in indices:
      dump.append( struct.pack('L',start+i) )
    else:
      dump.append( struct.pack('L',0x2e2e2e2e) )
  
  if len(dump) != Config.MMAP_LENGTH/Config.WORD_LENGTH :
    raise ValueError('error on length dump %d '%( len(dump) ) )  
  dump2 = ''.join(dump)
  if len(dump)*Config.WORD_LENGTH != len(dump2):
    raise ValueError('error on length dump %d dump2 %d'%( len(dump),len(dump2)) )
  stop = start + len(dump2)
  mmap = memory_mapping.MemoryMapping(start, stop, '-rwx', 0, 0, 0, 0, 'test_mmap')
  mmap2= memory_mapping.LocalMemoryMapping.fromBytebuffer( mmap, dump2)
  return mmap2


def makeSignature(seq):
  mmap = makeMMap(seq)
  mappings = memory_mapping.Mappings([mmap], 'test')
  sig = pattern.PointerIntervalSignature(mappings, 'test_mmap', Config)
  return sig  

class TestSignature(unittest.TestCase):

  def setUp(self):
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.mmap = makeMMap(self.seq)
    self.name = 'test_dump_1'
    self.sig = makeSignature(self.seq)

  def test_init(self):
    # forget about the start of the mmap  ( 0 to first pointer value) , its irrelevant
    self.assertEqual( list(self.sig.sig[1:]) , self.seq)

  def test_getAddressForPreviousPointer(self):
    self.assertEqual( self.sig.getAddressForPreviousPointer(0) , Config.MMAP_START)
    self.assertEqual( self.sig.getAddressForPreviousPointer(1) , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.sig.getAddressForPreviousPointer(2) , Config.MMAP_START+Config.STRUCT_OFFSET + 4)

  def test_len(self):
    self.assertEqual( len(self.sig) , len(self.seq)+1 )
  
# def tearDown(self):
#   os.remove('test_dump_1.pinned')
#   os.remove('test_dump_1.pinned.vaddr')
#   os.remove('test_signature_1.pinned')
#   os.remove('test_signature_1.pinned.vaddr')
      


class TestPinnedPointers(unittest.TestCase):

  def setUp(self):
    # PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 1 # offset of the pinned pointer sequence in the sig
    self.name = 'test_dump_1'
    self.sig = makeSignature(self.seq)
    self.pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)

  def test_init(self):
    self.assertEqual( self.pp.sequence, list(self.sig.sig[self.offset: self.offset+len(self.pp)]))

  def test_pinned(self):
    self.assertEqual( self.pp.pinned() , self.seq)
    self.assertEqual( len(self.pp.pinned(5)) , 5 )
    self.assertEqual( self.pp.pinned(3) , self.seq[0:3] )

  def test_len(self):
    len_seq = len(self.seq) 
    self.assertEqual( len(self.pp) , len_seq)

  def test_structlen(self):
    len_struct = sum(self.seq) +4
    self.assertEqual( self.pp.structLen() , len_struct)

  def test_cmp(self):
    seq = [4,4,8,128,4,8,4,4,12]
    pp1 = pattern.PinnedPointers(seq[1:], self.sig, self.offset+1)
    pp2 = pattern.PinnedPointers(seq[1:-1], self.sig, self.offset+1)
    pp3 = pattern.PinnedPointers(seq[:-1], self.sig, self.offset+1)
    pp4 = pattern.PinnedPointers(seq[:], self.sig, self.offset+1)

    seq = [4,8,4,128,4,8,4,4,12]
    pp5 = pattern.PinnedPointers(seq, self.sig, self.offset)

    self.assertNotEqual( pp1, self.pp)
    self.assertNotEqual( pp2, self.pp)
    self.assertNotEqual( pp3, self.pp)
    self.assertEqual( pp4, self.pp)
    self.assertNotEqual( pp5, self.pp)

 # def test_contains(self):
 #   seq = [4,4,8,128,4,8,4,4,12]
 #   pp1 = pattern.PinnedPointers(seq[1:], self.sig, self.offset+1)
 #   pp2 = pattern.PinnedPointers(seq[1:-1], self.sig, self.offset+1)
 #   pp3 = pattern.PinnedPointers(seq[:-1], self.sig, self.offset+1)
 #   pp4 = pattern.PinnedPointers(seq[:], self.sig, self.offset+1)#
 #   seq = [4,8,4,128,4,8,4,4,12]
 #   pp5 = pattern.PinnedPointers(seq, self.sig, self.offset)
 #
 #   #self.assertRaises( ValueError, r'ValueError', seq in self.pp )
 #   self.assertIn( pp1 , self.pp )
 #   self.assertIn( pp2 , self.pp )
 #   self.assertIn( pp3 , self.pp )
 #   self.assertIn( pp4 , self.pp )
 #   self.assertIn( pp5 , self.pp )

  def test_getAddress(self):
    self.assertEqual( self.pp.getAddress() , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.pp.getAddress(0) , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.pp.getAddress(1) , Config.MMAP_START+Config.STRUCT_OFFSET+sum(self.seq[:1]))
    self.assertEqual( self.pp.getAddress(2) , Config.MMAP_START+Config.STRUCT_OFFSET+sum(self.seq[:2]))



class TestAnonymousStructRange(unittest.TestCase):

  def setUp(self):
    # .....PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 1 # we need to skip the start -> first pointer part
    self.name = 'struct_1'
    self.sig = makeSignature(self.seq)
    self.pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)
    self.astruct = pattern.AnonymousStructRange(self.pp)

  def test_len(self):
    len_struct = sum(self.seq) + 4
    self.assertEqual( len(self.astruct) , len_struct)
    self.assertEqual( len(self.astruct) , self.pp.structLen() )
    
  def test_getPointersAddr(self):
    ret = self.astruct.getPointersAddr()
    tmp = [Config.MMAP_START, Config.STRUCT_OFFSET]
    tmp.extend(self.seq)
    addresses = [i for i in accumulate(tmp)]
    addresses.pop(0) # ignore address of start mmap

    self.assertEqual( len(ret) , len(addresses))
    self.assertEqual( ret , addresses)

  def test_getPointersValues(self):
    ret = self.astruct.getPointersValues()
    addrs = self.astruct.getPointersAddr()
    tmp = [Config.MMAP_START, Config.STRUCT_OFFSET]
    tmp.extend(self.seq)
    addresses = [i for i in accumulate(tmp)]
    addresses.pop(0) # ignore address of start mmap
    
    self.assertEqual( len(ret) , len(addresses))
    self.assertEqual( len(ret) , len(addrs))    
    # pointer value is the pointer vaddr on first test case
    for addr,val in zip(addrs,ret):
      memval = self.sig.mmap.readWord(addr)
      self.assertEqual( memval, val)
      self.assertEqual( addr , val)

  def test_contains(self):
    START = Config.MMAP_START+Config.STRUCT_OFFSET
    STOP = START+len(self.astruct)
    
    self.assertIn( START, self.astruct)
    self.assertIn( START+1, self.astruct)
    self.assertIn( STOP, self.astruct)
    self.assertIn( STOP-1, self.astruct)

    self.assertNotIn( STOP+1, self.astruct)
    self.assertNotIn( START-1, self.astruct)
  

















if __name__ == '__main__':
    unittest.main()

