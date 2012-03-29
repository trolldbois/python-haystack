#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import struct
import operator
import os
import unittest

from haystack import memory_mapping
from haystack.config import Config
from haystack.reverse import signature

Config.MMAP_START = 0x0c00000
Config.MMAP_STOP =  0x0c01000
Config.MMAP_LENGTH = 4096
Config.STRUCT_OFFSET = 44
#Config.cacheDir = os.path.normpath('./outputs/')


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
  values = []
  for i in range(0,Config.MMAP_LENGTH, Config.WORDSIZE): 
    if i in indices:
      dump.append( struct.pack('L',start+i) )
      values.append(start+i)
    else:
      dump.append( struct.pack('L',0x2e2e2e2e) )
  
  if len(dump) != Config.MMAP_LENGTH/Config.WORDSIZE :
    raise ValueError('error on length dump %d '%( len(dump) ) )  
  dump2 = ''.join(dump)
  if len(dump)*Config.WORDSIZE != len(dump2):
    raise ValueError('error on length dump %d dump2 %d'%( len(dump),len(dump2)) )
  stop = start + len(dump2)
  mmap = memory_mapping.MemoryMapping(start, stop, '-rwx', 0, 0, 0, 0, 'test_mmap')
  mmap2= memory_mapping.LocalMemoryMapping.fromBytebuffer( mmap, dump2)
  return mmap2, values




class TestPointerSearcher(unittest.TestCase):

  def setUp(self):
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.mmap, self.values = makeMMap(self.seq)
    self.name = 'test_dump_1'
    self.pointerSearcher = signature.PointerSearcher(self.mmap)

  def test_iter(self):
    iters = [value for value in self.pointerSearcher ]
    values = self.pointerSearcher.search()
    self.assertEqual( iters, values)
    self.assertEqual( self.values, values)
    self.assertEqual( self.values, iters)


class TestPointerEnumerator(unittest.TestCase):

  def setUp(self):
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.mmap, self.values = makeMMap(self.seq)
    self.name = 'test_dump_1'
    self.pointerEnum = signature.PointerEnumerator(self.mmap)

  def test_iter(self):
    values = [value for offset,value in self.pointerEnum ]
    offsets = [offset for offset,value in self.pointerEnum ]
    values_2 = [value for offset,value in self.pointerEnum.search() ]
    offsets_2 = [offset for offset,value in self.pointerEnum.search() ]

    self.assertEqual( values, values_2)
    self.assertEqual( offsets, offsets_2)
    self.assertEqual( self.values, values)
    self.assertEqual( self.values, values_2)

    nsig = [Config.MMAP_START+Config.STRUCT_OFFSET]
    nsig.extend(self.seq)
    indices = [ i for i in accumulate(nsig)]
    self.assertEqual( indices, offsets)
    self.assertEqual( indices, offsets_2)



if __name__ == '__main__':
    unittest.main()

