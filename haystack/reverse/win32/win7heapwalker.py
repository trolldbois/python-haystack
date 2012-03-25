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
from haystack.reverse.win32 import win7heap

log=logging.getLogger('win7heapwalker')


class Win7HeapWalker(heapwalker.HeapWalker):
  ''' '''
  def _initHeap(self):
    self._allocs = None
    self._heap = self._mapping.readStruct(self._mapping.start+self._offset, win7heap.HEAP)
    if not self._heap.loadMembers(self._mappings, -1):
      raise TypeError('HEAP.loadMembers returned False')

    log.debug('\n+ Heap @%x size: %d'%(self._mapping.start+self._offset, len(self._mapping)) )

  def getUserAllocations(self):
    ''' returns all User allocations (addr,size) '''
    if self._allocs is None:
      vallocs = self._getVirtualAllocations()
      chunks = self._getChunks()
      fth_chunks = self._getFrontendChunks()
      #
      lst = vallocs+chunks+fth_chunks
      myset = set(lst)
      if len(lst) != len(myset):
        log.warning('NON unique referenced chunks found. Please enquire. %d != %d'%(lstlen, setlen) )
      self._allocs = numpy.asarray(sorted(myset))
    return self._allocs
  
  def _getVirtualAllocations(self):
    allocated = [ block for block in self._heap.iterateListField(self._mappings, 'VirtualAllocdBlocks') ]
    log.debug( '+ %d vallocated blocks'%( len(allocated) ) )
    for block in allocated:
      log.debug( '\t- vallocated commit %x reserve %x'%(block.CommitSize, block.ReserveSize))
    #
    return allocated
  
  def _getChunks(self):
    chunks = [ chunk for chunk in self._heap.getChunks(self._mappings)]
    allocsize = sum( [c[1] for c in chunks ])
    log.debug('+ %d chunks, for %d bytes'%( len(chunks), allocsize ) )
    #
    return chunks
  
  def _getFrontendChunks(self):
    fth_chunks = [ chunk for chunk in self._heap.getFrontendChunks(self._mappings)]
    fth_allocsize = sum( [c[1] for c in fth_chunks ])
    log.debug('+ %d frontend chunks, for %d bytes'%( len(fth_chunks), fth_allocsize ) )
    #
    return fth_chunks


def getUserAllocations(mappings, heap, filterInUse=False):
  ''' list user allocations '''
  walker = Win7HeapWalker(mappings, heap, 0)
  for chunk_addr, chunk_size in walker.getUserAllocations():
    yield (chunk_addr, chunk_size)
  raise StopIteration

 

