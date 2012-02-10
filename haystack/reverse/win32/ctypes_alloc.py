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

log=logging.getLogger('ctypes_win32_malloc')


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



USHORT = ctypes.c_ushort
UCHAR  = ctypes.c_ubyte

class FLAGS:
  HEAP_ENTRY_BUSY = 0x01
  HEAP_ENTRY_EXTRA_PRESENT = 0x02
  HEAP_ENTRY_FILL_PATTERN = 0x04
  HEAP_ENTRY_VIRTUAL_ALLOC = 0x08
  HEAP_ENTRY_LAST_ENTRY = 0x10
  HEAP_ENTRY_SETTABLE_FLAG1 = 0x20
  HEAP_ENTRY_SETTABLE_FLAG2 = 0x40
  HEAP_ENTRY_SETTABLE_FLAG3 = 0x80
  text = {
        0x01: 'HEAP_ENTRY_BUSY',
        0x02: 'HEAP_ENTRY_EXTRA_PRESENT',
        0x04: 'HEAP_ENTRY_FILL_PATTERN',
        0x08: 'HEAP_ENTRY_VIRTUAL_ALLOC',
        0x10: 'HEAP_ENTRY_LAST_ENTRY',
        0x20: 'HEAP_ENTRY_SETTABLE_FLAG1',
        0x40: 'HEAP_ENTRY_SETTABLE_FLAG2',
        0x80: 'HEAP_ENTRY_SETTABLE_FLAG3',
        }


def search(mappings, heap, filterInuse=False ):
  orig_addr = heap.start
  
  while orig_addr in heap:
    #print 'next', 
    chunk = heap.readStruct(orig_addr, malloc_chunk)
    ret = False
    try:
      ret = chunk.loadMembers(mappings, 10, orig_addr)
    except ValueError,e:
      pass
    if not ret:
      orig_addr += Config.WORDSIZE
      continue
      #raise ValueError('heap dos not start with an malloc_chunk')
    #data = chunk.getUserData(mappings, orig_addr)
    #print chunk.toString(''), 'real_size = ', chunk.real_size()
    #print hexdump(data)
    #print ' ---------------- '
    
    prev_size = chunk.size
    prev = chunk
    
    #check next
    try:
      while True:
        next, next_addr = chunk.getNextChunk(mappings, orig_addr)
        if next.prev_size != prev_size:
          #print '************* size differs'
          raise ValueError
        #print ' next_addr 0x%x, size: %x'%(next_addr, next.size)   
        ret = next.loadMembers(mappings, 10, next_addr)
        if not ret:
          print '************* LOAD FAILED'
          raise ValueError
        print next.toString(''), 'real_size = ', next.real_size()
        #print test.hexdump(next.getUserData(mappings, next_addr))
        print ' ---------------- '
        print 'next', (next.get_mem_addr(next_addr), next.get_mem_size()) 
        # next loop
        orig_addr = next_addr
        chunk = next
        prev_size = chunk.size
    except ValueError,e:
      orig_addr += Config.WORDSIZE
      continue

  

def getUserAllocations(mappings, heap, filterInuse=False):
  '''   Lists all (addr, size) of allocated space by malloc_chunks.
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
    if chunk.check_inuse():
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
      if next.check_inuse():
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
    "Size" - USHORT, 2 octets : taille du chunk courant. Elle correspond à un nombre de cellules de 8 octets occupées par le chunk. Lors de la demande d'allocation, la taille demandée est arrondie à un multiple de 8 (supérieur ou égal), auquel s'ajoutent les 8 octets necessaires au stockage des champs du chunk. La taille stockée ici répond donc à l'opération (tailledemandee + 7) >> 3 + 1, soit 65 pour 512 octets, 18 pour 129, etc ;
    "PreviousSize" - USHORT, 2 octets : taille du chunk précédant, possède les mêmes caractéristiques que "Self size" ;
    "SegmentIndex" - UCHAR, 1 octet : indice du segment auquel appartient le chunk, en référence au tableau des segments du tas ;
    "Flags" - UCHAR, 1 octet : indicateurs des propriétés du chunk, chaque bit positionné à 1 de cet octet faisant état d'une caractéristique particulière du chunk, ils peuvent être trouvés sur le web (les plus utiles seront détaillés par la suite) :
        0x01, HEAP_ENTRY_BUSY
        0x02, HEAP_ENTRY_EXTRA_PRESENT
        0x04, HEAP_ENTRY_FILL_PATTERN
        0x08, HEAP_ENTRY_VIRTUAL_ALLOC
        0x10, HEAP_ENTRY_LAST_ENTRY
        0x20, HEAP_ENTRY_SETTABLE_FLAG1
        0x40, HEAP_ENTRY_SETTABLE_FLAG2
        0x80, HEAP_ENTRY_SETTABLE_FLAG3
    "UnusedBytes" - UCHAR, 1 octet : nombre d'octets non utilisés dans le buffer alloué, égal à la taille allouée à laquelle est soustraite la taille demandée - information d'une utilité très relative ;
    "SmallTagIndex" - UCHAR, 1 octet : uniquement utilisé en mode debug.


struct malloc_chunk {

  USHORT size;  //2
  USHORT prev_size; //2

  UCHAR segment_index;
  UCHAR flags;
  UCHAR UnusedBytes;
  UCHAR  SmallTagIndex;
};

0000000 0000 0000 0011 0000 beef dead 1008 0927
0000010 0000 0000 0019 0000 beef dead 1010 1010
0000020 1018 0927 1010 1010 beef dead 0fd9 0002
0000030 0000 0000 0000 0000 0000 0000 0000 0000

  '''
  def get_mem_addr(self, orig_addr):
    return orig_addr + 8

  def get_mem_size(self):
    return self.real_size() - 8 - self.unused_bytes
    
  def real_size(self):
    return self.size * 8
  def real_prev_size(self):
    return self.prev_size * 8

  def next_addr(self, orig_addr):
    return orig_addr + self.real_size()
  def prev_addr(self, orig_addr):
    return orig_addr - self.real_prev_size()

  def check_inuse(self):
    ''' if flags busy, inuse == true  '''
    return self.flags & FLAGS.HEAP_ENTRY_BUSY

  def check_prev_inuse(self, mappings, orig_addr):
    ''' if flags busy, inuse == true  '''
    prev_addr = self.prev_addr(orig_addr) 
    mmap = model.is_valid_address_value(prev_addr, mappings)
    if not mmap:
      return 0
    prev = mmap.readStruct( prev_addr, malloc_chunk )
    return prev.flags & FLAGS.HEAP_ENTRY_BUSY

  
  def isValid(self, mappings, orig_addr):

    # get the real data headers. size of fields of based on struct definition
    real_size = self.real_size()
    if self.size == 0:
      return False
      
    log.debug('self.size %d'% self.size )
    log.debug('self.prev_size %d'% self.prev_size )
    log.debug('real_size %d'% self.real_size() )
    log.debug('real_prev_size %d'% self.real_prev_size() )

    ## inuse : to know if inuse, you have to look at next_chunk.size & PREV_SIZE bit
    inuse = self.check_inuse() 
    log.debug('is chunk in use ?: %s'% bool(inuse) )
    
    '''
    if self.size % Config.WORDSIZE != 0:
      # not a good value
      log.debug('size is not a WORDSIZE moduli')
      return False
    if self.prev_size % Config.WORDSIZE != 0:
      # not a good value
      log.debug('prev_size is not a WORDSIZE moduli')
      return False
    '''
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

    if self.check_prev_inuse(mappings, orig_addr) : # if in use, prev_size is not readable
      #self.prev_size = 0
      pass
    else:
      prev,prev_addr = self.getPrevChunk(mappings, orig_addr)
      if prev_addr is None:
        return False

    return True
  
  def getPrevChunk(self, mappings, orig_addr):
    mmap = model.is_valid_address_value(orig_addr, mappings)
    if not mmap:
      raise ValueError
    if self.prev_size > 0 :
      prev_addr = self.prev_addr(orig_addr)
      prev_chunk = mmap.readStruct(prev_addr, malloc_chunk )
      model.keepRef( prev_chunk, malloc_chunk, prev_addr)
      return prev_chunk, prev_addr
    return None, None
      
  def getNextChunk(self, mappings, orig_addr):
    mmap = model.is_valid_address_value(orig_addr, mappings)
    if not mmap:
      raise ValueError
    if self.size > 0 :
      next_addr = self.next_addr(orig_addr)
      next_chunk = mmap.readStruct(next_addr, malloc_chunk )
      model.keepRef( next_chunk, malloc_chunk, next_addr)
      return next_chunk, next_addr
    return None, None



malloc_chunk._fields_ = [
    ( 'size' , USHORT ), #  2
    ( 'prev_size' , USHORT ), # 2
    ( 'segment_index', UCHAR ),
    ( 'flags', UCHAR ),
    ( 'unused_bytes', UCHAR ),
    ( 'small_tag_index', UCHAR ),
    # totally virtual
   ]
# make subclass for empty or inuse..

# cant use 2** expectedValues, there is a mask on sizes...
malloc_chunk.expectedValues = {    }




#model.registerModule(sys.modules[__name__])

  

