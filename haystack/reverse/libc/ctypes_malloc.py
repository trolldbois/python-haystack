#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

from haystack import model, memory_mapping
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress
from haystack.model import LoadableMembers,RangeValue,NotNull,CString, IgnoreMember, PerfectMatch

from haystack.config import Config
import struct

log=logging.getLogger('ctypes_malloc')


SIZE_SZ = Config.WORDSIZE
MIN_CHUNK_SIZE    = 4 * SIZE_SZ
MALLOC_ALIGNMENT  = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)


class mallocStruct(LoadableMembers):
  ''' defines classRef '''
  pass



if Config.WORDSIZE == 4:
  UINT = ctypes.c_uint32
elif Config.WORDSIZE == 8:
  UINT = ctypes.c_uint64

def getUserAllocations(mappings, heap, filterInuse=False):
  ''' 
  Lists all (addr, size) of allocated space by malloc_chunks.
  '''
  #allocations = [] # index, size
  orig_addr = heap.start
  
  chunk = heap.readStruct(orig_addr, malloc_chunk)
  ret = chunk.loadMembers(mappings, 10, orig_addr)
  if not ret:
    raise ValueError('heap dos not start with an malloc_chunk')
  #data = chunk.getUserData(mappings, orig_addr)
  #print chunk.toString(''), 'real_size = ', chunk.real_size()
  #print hexdump(data)
  #print ' ---------------- '
  if filterInuse:
    if chunk.check_inuse(mappings, orig_addr):
      yield  (chunk.get_mem_addr(orig_addr), chunk.get_mem_size()) 
  else:
    yield  (chunk.get_mem_addr(orig_addr), chunk.get_mem_size()) 

  while True:
    next, next_addr = chunk.getNextChunk(mappings, orig_addr)
    if next_addr is None:
      #print 'no next chunk'
      break
    #print ' next_addr 0x%x, size: %x'%(next_addr, next.size)   
    ret = next.loadMembers(mappings, 10, next_addr)
    if not ret:
      raise ValueError
    #print next.toString(''), 'real_size = ', next.real_size()
    #print test.hexdump(next.getUserData(mappings, next_addr))
    #print ' ---------------- '
    if filterInuse:
      if next.check_inuse(mappings, next_addr):
        yield  (next.get_mem_addr(next_addr), next.get_mem_size()) 
    else:
      yield (next.get_mem_addr(next_addr), next.get_mem_size()) 
    # next loop
    orig_addr = next_addr
    chunk = next

  raise StopIteration


def isMallocHeap(mappings, mapping):
  """test if a mapping is a malloc generated heap"""
  orig_addr = mapping.start
  chunk = mapping.readStruct(orig_addr, malloc_chunk)
  ret = chunk.loadMembers(mappings, 10, orig_addr)
  if not ret:
    return False
  return True




class malloc_chunk(mallocStruct):
  '''FAKE python representation of a struct malloc_chunk

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

0000000 0000 0000 0011 0000 beef dead 1008 0927
0000010 0000 0000 0019 0000 beef dead 1010 1010
0000020 1018 0927 1010 1010 beef dead 0fd9 0002
0000030 0000 0000 0000 0000 0000 0000 0000 0000

  '''
  def get_mem_addr(self, orig_addr):
    return orig_addr + 2*Config.WORDSIZE

  def get_mem_size(self):
    return self.real_size() - Config.WORDSIZE
    
  def real_size(self):
    return (self.size & ~SIZE_BITS)

  def next_addr(self, orig_addr):
    return orig_addr + self.real_size()
  def prev_addr(self, orig_addr):
    return orig_addr - self.prev_size

  def check_prev_inuse(self):
    return self.size & PREV_INUSE

  def check_inuse(self, mappings, orig_addr):
    '''extract p's inuse bit
    doesnt not work on the top one
    '''
    next_addr = self.next_addr(orig_addr) + ctypes.sizeof(memory_mapping.MemoryMapping.WORDTYPE)
    mmap = model.is_valid_address_value(next_addr, mappings)
    if not mmap:
      return 0
      #raise ValueError()
    next_size = mmap.readWord( next_addr)
    #print 'next_size',next_size, '%x'%next_addr
    return next_size & PREV_INUSE

  
  def isValid(self, mappings, orig_addr):

    # get the real data headers. size of fields of based on struct definition
    #  (self.prev_size,  self.size) = struct.unpack_from("<II", mem, 0x0)
    real_size = self.real_size()
    
    log.debug('self.prev_size %d'% self.prev_size )
    log.debug('self.size %d'% self.size )
    log.debug('real_size %d'% real_size )

    ## inuse : to know if inuse, you have to look at next_chunk.size & PREV_SIZE bit
    inuse = self.check_inuse(mappings, orig_addr) 
    log.debug('is chunk in use ?: %s'% bool(inuse) )
    
    if real_size % Config.WORDSIZE != 0:
      # not a good value
      log.debug('real_size is not a WORDSIZE moduli')
      return False
    
    return True

  def loadMembers(self, mappings, maxDepth, orig_addr):

    if maxDepth == 0:
      log.debug('Maximum depth reach. Not loading any deeper members.')
      log.debug('Struct partially LOADED. %s not loaded'%(self.__class__.__name__))
      return True
    maxDepth-=1
    log.debug('%s loadMembers'%(self.__class__.__name__))
    if not self.isValid(mappings, orig_addr):
      return False
    
    # update virtual fields
    next, next_addr = self.getNextChunk(mappings, orig_addr)
    #if next_addr is None: #most of the time its not
    #  return True

    if self.check_prev_inuse() : # if in use, prev_size is not readable
      #self.prev_size = 0
      pass
    else:
      prev,prev_addr = self.getPrevChunk(mappings, orig_addr)
      if prev_addr is None:
        return False

    return True
  
  def getPrevChunk(self, mappings, orig_addr):
    ## do prev_chunk
    if self.check_prev_inuse():
      raise TypeError('Previous chunk is in use. can read its size.')
    mmap = model.is_valid_address_value(orig_addr, mappings)
    if not mmap:
      raise ValueError
    if self.prev_size > 0 :
      prev_addr = orig_addr - self.prev_size
      prev_chunk = mmap.readStruct(prev_addr, malloc_chunk )
      model.keepRef( prev_chunk, malloc_chunk, prev_addr)
      return prev_chunk, prev_addr
    return None, None
      
  def getNextChunk(self, mappings, orig_addr):
    ## do next_chunk
    mmap = model.is_valid_address_value(orig_addr, mappings)
    if not mmap:
      raise ValueError
    next_addr = orig_addr + self.real_size()
    # check if its in mappings
    if not model.is_valid_address_value(next_addr, mappings):
      return None,None
    next_chunk = mmap.readStruct(next_addr, malloc_chunk )
    model.keepRef( next_chunk, malloc_chunk, next_addr)
    return next_chunk, next_addr



malloc_chunk._fields_ = [
    ( 'prev_size' , UINT ), #  INTERNAL_SIZE_T
    ( 'size' , UINT ), #  INTERNAL_SIZE_T with some flags
    # totally virtual
   ]
# make subclass for empty or inuse..

# cant use 2** expectedValues, there is a mask on sizes...
malloc_chunk.expectedValues = {    }




model.registerModule(sys.modules[__name__])


