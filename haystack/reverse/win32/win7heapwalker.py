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
  '''   
  # While all allocations over 0xFE00 blocks are handled by VirtualAlloc()/VirtualFree(),
  # all memory management that is greater than 0x800 blocks is handled by the back-end; 
  # along with any memory that cannot be serviced by the front-end.
  '''
  def _init_heap(self):
    self._allocs = None
    self._child_heaps = None
    self._heap = self._mapping.readStruct(self._mapping.start+self._offset, win7heap.HEAP)
    if not self._heap.loadMembers(self._mappings, -1):
      raise TypeError('HEAP.loadMembers returned False')

    log.debug('+ Heap @%0.8x size: %d # %s'%(self._mapping.start+self._offset, len(self._mapping), self._mapping) )
    #print '+ Heap @%0.8x size:%d FTH_Type:0x%x maskFlag:0x%x index:0x%x'%(self._mapping.start+self._offset, 
    #              len(self._mapping), self._heap.FrontEndHeapType, self._heap.EncodeFlagMask, self._heap.ProcessHeapsListIndex) 
    # placeholders
    self._backend_committed = None
    self._backend_free = None
    self._fth_committed = None
    self._fth_free = None
    self._valloc_committed = None
    self._valloc_free = None
    return

  def get_user_allocations(self):
    ''' returns all User allocations (addr,size) '''
    if self._allocs is None:
      vallocs = self._get_virtualallocations()
      chunks, free_chunks = self._get_chunks()
      fth_chunks = self._get_frontend_chunks()
      # DEBUG : delete replace by iterator on the 3 iterator
      lst = vallocs+chunks+fth_chunks
      myset = set(lst)
      if len(lst) != len(myset):
        log.warning('NON unique referenced chunks found. Please enquire. %d != %d'%(lstlen, setlen) )
      self._allocs = numpy.asarray(sorted(myset))
      # found targetted mappings...
      #print set([ self._mappings.getMmapForAddr(a[0]) for a in self._allocs if a[0] not in self._mapping])
    return self._allocs

  def get_heap_children_mmaps(self):
    ''' use free lists to establish the hierarchy between mmaps'''
    if self._child_heaps is None:
      child_heaps = set()
      for x,s in self._get_freelists():
        m = self._mappings.getMmapForAddr(x)
        if (m != self._mapping) and ( m not in child_heaps):
          log.debug( 'mmap 0x%0.8x is extended heap space from 0x%0.8x'%(m.start, self._mapping.start) )
          child_heaps.add(m)
          pass
      self._child_heaps = child_heaps
    # TODO: add information from used user chunks
    return self._child_heaps


  def _get_virtualallocations(self):
    if (self._valloc_committed, self._valloc_free) == (None, None):
      self._valloc_committed = [ block for block in self._heap.iterateListField(self._mappings, 'VirtualAllocdBlocks') ]
      # DEBUG : delete replace by iterator
      log.debug( '\t+ %d vallocated blocks'%( len(self._valloc_committed) ) )
      #for block in allocated: #### BAD should return (vaddr,size)
      #  log.debug( '\t\t- vallocated commit %x reserve %x @%0.8x'%(block.CommitSize, block.ReserveSize, ctypes.addressof(block)))
      #
    return self._valloc_committed, self._valloc_free
  
  def _get_chunks(self):
    if (self._backend_committed, self._backend_free) == (None, None):
      self._backend_committed, self._backend_free = self._heap.getChunks(self._mappings)
      allocsize = sum( [c[1] for c in self._backend_committed ])
      freesize = sum( [c[1] for c in self._backend_free ])
      log.debug('\t+ Segment Chunks: alloc: %0.4d [%0.5d B] free: %0.4d [%0.5d B]'%( 
                          len(self._backend_committed), allocsize, len(self._backend_free), freesize ) )
      #
      #for chunk in allocated:
      #  log.debug( '\t\t- chunk @%0.8x size:%d'%(chunk[0], chunk[1]) )
    return self._backend_committed, self._backend_free
  
  def _get_frontend_chunks(self):
    if (self._fth_committed, self._fth_free) == (None, None):
      self._fth_committed, self._fth_free = self._heap.getFrontendChunks(self._mappings)
      fth_commitsize = sum( [c[1] for c in self._fth_committed ])
      fth_freesize = sum( [c[1] for c in self._fth_free ])
      log.debug('\t+ %d frontend chunks, for %d bytes'%( len(self._fth_committed), fth_commitsize ) )
      log.debug('\t+ %d frontend free chunks, for %d bytes'%( len(self._fth_free), fth_freesize ) )
      #
      #for chunk in fth_chunks:
      #  log.debug( '\t\t- fth_chunk @%0.8x size:%d'%(chunk[0], chunk[1]) )
    return self._fth_committed, self._fth_free

  def _get_freelists(self):
    # FIXME check if freelists and committed backend collides.
    free_lists = [ (freeblock_addr, size) for freeblock_addr, size in self._heap.getFreeLists(self._mappings)]
    freesize = sum( [c[1] for c in free_lists ])
    log.debug('\t+ freeLists: free: %0.4d [%0.5d B]'%( len(free_lists), freesize ) )
    return free_lists
  
  def _get_BlocksIndex(self):
    pass 
    


def get_user_allocations(mappings, heap, filterInUse=False,p1=1,p2=0):
  ''' list user allocations '''
  walker = Win7HeapWalker(mappings, heap, 0)
  for chunk_addr, chunk_size in walker.get_user_allocations():
    yield (chunk_addr, chunk_size)
  raise StopIteration

# TODO : 
#def getAllUserAllocations(mappings):
#def _init_Win7_MemoryMappings_Heaps(mappings):
#  found=[]
#  for mapping in self._mappings:
#    addr = mapping.start
#    heap = mapping.readStruct( addr, HEAP )
#    if addr in map(lambda x:x[0] , self._known_heaps):
#      self.assertTrue(  heap.loadMembers(self._mappings, -1), "We expected a valid hit at @%x"%(addr) )
#      found.append(addr, )
#    else:
#      try:
#        ret = heap.loadMembers(self._mappings, -1)
#        self.assertFalse( ret, "We didnt expected a valid hit at @%x"%(addr) )
#      except ValueError,e:
#        self.assertRaisesRegexp( ValueError, 'error while loading members')
#
#  found.sort()
#
# TODO : change the mappings file ?
#

def isHeap(mappings, mapping):
  """test if a mapping is a heap"""
  # todo check _heap.ProcessHeapsListIndex
  addr = mapping.start
  heap = mapping.readStruct( addr, win7heap.HEAP )
  load = heap.loadMembers(mappings, -1)
  return load

def readHeap(mapping):
  """ return a ctypes heap struct mapped at address on the mapping"""
  addr = mapping.start
  heap = mapping.readStruct( addr, win7heap.HEAP )
  return heap




