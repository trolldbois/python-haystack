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
      dump.append( struct.pack('L',start+(i*Config.WORD_LENGTH)) )
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
  sig = pattern.Signature(mmap=mmap, dumpFilename='test_signature_1')
  sig._load()
  return sig  

class TestSignature(unittest.TestCase):

  def setUp(self):
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.mmap = makeMMap(self.seq)
    self.name = 'test_dump_1'


  def test_init(self):
    sig = pattern.Signature(mmap=self.mmap, dumpFilename=self.name)
    sig._load()
    # forget about the start of the mmap  ( 0 to first pointer value) , its irrelevant
    self.assertEqual( list(sig.sig[1:]) , self.seq)

  def test_getAddressForPreviousPointer(self):
    sig = pattern.Signature(mmap=self.mmap, dumpFilename=self.name)
    sig._load()
    self.assertEqual( sig.getAddressForPreviousPointer(1) , Config.MMAP_START+Config.STRUCT_OFFSET)
  
# def tearDown(self):
#   os.remove('test_dump_1.pinned')
#   os.remove('test_dump_1.pinned.vaddr')
#   os.remove('test_signature_1.pinned')
#   os.remove('test_signature_1.pinned.vaddr')
      


class TestPinnedPointers(unittest.TestCase):

  def setUp(self):
    # PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 0
    self.name = 'test_dump_1'
    self.sig = makeSignature(self.seq)

  def test_init(self):
    pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)
    self.assertEqual( list(self.sig.sig[1: len(self.seq)+1]) , self.seq)

  def test_len(self):
    pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)
    len_seq = len(self.seq) 
    self.assertEqual( len(pp) , len_seq)

  def test_pinned(self):
    pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)
    self.assertEqual( pp.pinned() , self.seq)
    self.assertEqual( len(pp.pinned(5)) , 5 )
    self.assertEqual( pp.pinned(3) , self.seq[0:3] )

      


class TestAnonymousStructRange(unittest.TestCase):

  def setUp(self):
    # PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 0
    self.name = 'struct_1'
    self.sig = makeSignature(self.seq)
    self.pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)

  def test_len(self):
    astruct = pattern.AnonymousStructRange(self.pp)
    len_struct = sum(self.seq) + 4
    self.assertEqual( len(astruct) , len_struct)


if __name__ == '__main__':
    unittest.main()

