#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import sys

import numpy 
from haystack import model
from haystack.reverse import heapwalker
from haystack.reverse.libc import ctypes_malloc

log=logging.getLogger('libcheapwalker')


class LibcHeapWalker(heapwalker.HeapWalker):
  ''' '''
  def _initHeap(self):
    log.debug('+ Heap @%x size: %d # %s'%(self._mapping.start+self._offset, len(self._mapping), self._mapping) )

  def getUserAllocations(self):
    ''' returns all User allocations (addr,size) '''
    for x in ctypes_malloc.getUserAllocations(self._mappings, self._mapping):
      yield x


def getUserAllocations(mappings, heap, filterInUse=False):
  ''' list user allocations '''
  walker = LibcHeapWalker(mappings, heap, 0)
  for chunk_addr, chunk_size in walker.getUserAllocations():
    yield (chunk_addr, chunk_size)
  raise StopIteration






