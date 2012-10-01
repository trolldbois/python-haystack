#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
""" Win 7 heap structure - from LGPL metasm"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

from haystack.config import Config
if Config._WORDSIZE is None:
  raise ValueError('You should not raise me')

''' insure ctypes basic types are subverted '''
from haystack import model
from haystack import utils

from haystack.reverse.win32 import win7heap_generated as gen

import ctypes
import struct
import logging, sys

log=logging.getLogger('win7heap')

# ============== Internal type defs ==============

################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################





############# Start expectedValues and methods overrides #################

## fix partial declaration
_HEAP_LOCK._fields_ = [
  ('voidme', ctypes.c_ubyte),
  ]

_LFH_BLOCK_ZONE._fields_ = [
  ('voidme', ctypes.c_ubyte),
  ]


## HEAP_SEGMENT

_HEAP_SEGMENT.expectedValues = {
  'SegmentSignature':[0xffeeffee],
# Cannot just ignore it... need to load it.
#  'LastValidEntry': utils.IgnoreMember,
}

#_HEAP_SEGMENT.UCRSegmentList. points to _HEAP_UCR_DESCRIPTOR.SegmentEntry.
#_HEAP_UCR_DESCRIPTOR.SegmentEntry. points to _HEAP_SEGMENT.UCRSegmentList.

_HEAP_SEGMENT._listHead_ = [  ('UCRSegmentList', _HEAP_UCR_DESCRIPTOR, 'ListEntry', -8),]
##_HEAP_SEGMENT._listHead_ = [  ('UCRSegmentList', _HEAP_UCR_DESCRIPTOR, 'SegmentEntry'),]
#_HEAP_SEGMENT._listMember_ = ['SegmentListEntry']

## LastValidEntry can be out of mappings
# (is_valid_address: 0x01f00000 0x01f12000 rw- 0x00000000 fe:01 24422442 None)
#DEBUG:basicmodel:ptr: LastValidEntry <class 'haystack.reverse.win32.win7heap_generated.LP__HEAP_ENTRY'>
# <haystack.reverse.win32.win7heap_generated.LP__HEAP_ENTRY object at 0x904989c> 0x2000000 INVALID


# For LastValidEntry, we need a special treatment.
# If the pointer is valid, we should load it.
# if the pointer is out of mapping, ignore it.
# Cannot just ignore it... need to load it.

def _HEAP_SEGMENT_isValidAttr(self,attr,attrname,attrtype,mappings):
  #log.debug('_isValidAttr attrname : %s'%(attrname))
  if attrname == 'LastValidEntry':
    return True # ignore
  else:
    return super(_HEAP_SEGMENT,self)._isValidAttr(attr,attrname,attrtype,mappings)

_HEAP_SEGMENT._isValidAttr = _HEAP_SEGMENT_isValidAttr

def _HEAP_SEGMENT_loadMember(self,attr,attrname,attrtype,mappings, maxDepth):
  #log.debug('_loadMember attrname : %s'%(attrname))
  if attrname == 'LastValidEntry':
    # isPointerType code.
    _attrType = model.get_subtype(attrtype)
    attr_obj_address = utils.getaddress(attr)
    ####
    memoryMap = utils.is_valid_address( attr, mappings, _attrType)
    if(not memoryMap):
      log.debug("LastValidEntry out of mapping - 0x%lx - ignore "%(attr_obj_address ))
      return True
    from haystack.model import getRef, keepRef, delRef # TODO CLEAN
    ref=getRef(_attrType,attr_obj_address)
    if ref:
      #log.debug("%s %s loading from references cache %s/0x%lx"%(attrname,attr,_attrType,attr_obj_address ))
      #DO NOT CHANGE STUFF SOUPID attr.contents = ref
      return True
    #log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, memoryMap ))
    ##### Read the struct in memory and make a copy to play with.
    ### ERRROR attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address, _attrType ))
    contents=memoryMap.readStruct(attr_obj_address, _attrType )
    # save that validated and loaded ref and original addr so we dont need to recopy it later
    keepRef( contents, _attrType, attr_obj_address)
    #log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr, attr_obj_address, (utils.getaddress(attr))   ))
    # recursive validation checks on new struct
    if not bool(attr):
      log.warning('Member %s is null after copy: %s'%(attrname,attr))
      return True
    # go and load the pointed struct members recursively
    if not contents.loadMembers(mappings, maxDepth):
      log.debug('member %s was not loaded'%(attrname))
      #invalidate the cache ref.
      delRef( _attrType, attr_obj_address)
      return False
    return True
  else:
    return super(_HEAP_SEGMENT,self)._loadMember(attr,attrname,attrtype,mappings, maxDepth)


_HEAP_SEGMENT._loadMember = _HEAP_SEGMENT_loadMember

###### HEAP

_HEAP.expectedValues = {
  'Signature':[0xeeffeeff],
  'FrontEndHeapType': [0,1,2]
}
_HEAP._listHead_ = [  ('SegmentList', _HEAP_SEGMENT, 'SegmentListEntry', -16 ),
                      ('VirtualAllocdBlocks', _HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8 )]
#HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
#SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
# you need to ignore the Head in the iterator...



def _HEAP_getSegmentList(self, mappings):
  ''' list all heap entries attached to one Heap structure. 
  
  Heap.SegmentList points to the _LIST_ENTRY of Heap.Segment. +0x10
  Iteration on SegmentList should return Segment.
  Offset is needed and provided through _listHead_.
  FIXME: offset could/should be automated by declaring child _LIST_ENTRY fieldname (SegmentListEntry)
    listmodel.py:164
  
  BUT iteration should stop on sentinel values.
    Internal algoritm of iterateListField will not use the root LIST_Entry address as a valid object.
    It will use it as a sentinel.
    If there is another sentinel... bad luck....
  
  Heap.Segment.Entry is a valid Heap_entry, addr+size*8 should point to FirstValidEntry.
  '''
  allocated = list()
  free = list()
  #log.debug('%s'%(self))
  for segment in self.iterateListField( mappings, 'SegmentList'):
    #for segment_addr in self.SegmentList._iterateList( mappings):
    segment_addr = segment._orig_addr_
    first_addr = utils.getaddress(segment.FirstEntry)
    last_addr = utils.getaddress(segment.LastValidEntry)

    log.debug( 'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x'%( segment_addr, first_addr, last_addr) )

    skiplist = dict()
    for ucr in segment.iterateListField( mappings, 'UCRSegmentList'):
      ucr_addr = ucr._orig_addr_
      seg_addr = utils.getaddress( ucr.SegmentEntry.FLink)
      log.debug("Heap.Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x"%(ucr_addr, ucr.Address, ucr.Size*8))
      #log.debug("%s"%(ucr.SegmentEntry)) # TODO - CHECK FOR CONSISTENCY ? more heapdebug than haystack debug
      skiplist[ucr.Address] = ucr.Size*8

    # # obviously not usable, first entry sits on heap header.
    #chunk_header = segment.Entry
    #if self.EncodeFlagMask: #heap.EncodeFlagMask
    #  log.debug('EncodeFlagMask is set on the HEAP. decoding is needed.')
    #  chunk_header = _HEAP_ENTRY_decode(chunk_header, self)
    #chunk_addr = segment._orig_addr_ + utils.offsetof(_HEAP_SEGMENT, 'Entry')
    #log.debug('Heap.Segment.Entry: 0x%0.8x\n%s'%( chunk_addr, chunk_header))

    #print segment

    from haystack.model import getRef# TODO CLEAN
    chunk_addr = first_addr
    while (chunk_addr < last_addr):
      if chunk_addr in skiplist:
        size = skiplist[chunk_addr]
        log.debug('Skipping 0x%0.8x - skip %0.5x bytes to 0x%0.8x'%(chunk_addr, size, chunk_addr+size))
        chunk_addr += size
        continue
      chunk_header = getRef(_HEAP_ENTRY, chunk_addr)
      if chunk_header is None: # force read it
        chunk_header = _get_chunk(mappings, self, chunk_addr)
      if self.EncodeFlagMask: #heap.EncodeFlagMask
        chunk_header = _HEAP_ENTRY_decode(chunk_header, self)
      #log.debug('\t\tEntry: 0x%0.8x\n%s'%( chunk_addr, chunk_header))
      
      if ((chunk_header.Flags & 1) == 1):
        log.debug('Chunk 0x%0.8x is in use size: %0.5x'%(chunk_addr, chunk_header.Size*8))
        allocated.append( (chunk_addr, chunk_header.Size*8) )
      else:
        log.debug('Chunk 0x%0.8x is FREE'%(chunk_addr))
        free.append( (chunk_addr, chunk_header.Size*8) )        
        pass
      chunk_addr += chunk_header.Size*8
      
    
  return (allocated, free)

_HEAP.getSegmentList = _HEAP_getSegmentList

#@deprecated
def _HEAP_scan_heap_segment(self, mappings, entry_addr, size):
  res = list()
  off = 0
  encsize, flags, unused = self.getChunkInfo()
  chunks = 0
  bad=0
  while off < size:
    m = mappings.getMmapForAddr( entry_addr+off )
    if not bool(m) :
      # out of mapping LastValidEntry - do not load
      # log.info('_HEAP scan-heap on @%x + off:%x = @%x- error'%(entry_addr, off, entry_addr+off))
      break
    he = m.readStruct(entry_addr+off, _HEAP_ENTRY)
    sz = (he.Size ^ encsize)*8
    if (he.Flags ^ flags) & 1 == 1: # allocated or not ?
      #chunks[entry_addr+off+ _HEAP_SEGMENT.Entry.size] = sz - (he.UnusedBytes ^ unused)
      chunks+=1
      #log.debug('Found a chunk at @%x size %x'% (entry_addr+off+ _HEAP_SEGMENT.Entry.size, sz - (he.UnusedBytes ^ unused) ) )
      res.append( ((entry_addr+off+ _HEAP_SEGMENT.Entry.size) , (sz - (he.UnusedBytes ^ unused)) ) )
    else:
      log.debug('(he.Flags ^ flags) & 1 != 1: %s'% ((he.Flags ^ flags) & 1) ) # HEAP_ENTRY_BUSY = 0x1
      bad+=1
    off += sz
  log.debug('Found %d allocated chunks and %d with bad flags'%(chunks, bad) )
  return res


#@deprecated
def _HEAP_getChunkInfo(self):
	if self.EncodeFlagMask != 0:
		return (self.Encoding.Size, self.Encoding.Flags, self.Encoding.UnusedBytes)
	else:
	  return (0,0,0)

#_HEAP.scan_heap_segment = _HEAP_scan_heap_segment
#_HEAP.getChunkInfo = _HEAP_getChunkInfo

'''//position 0x7 in the header denotes
//whether the chunk was allocated via
//the front-end or the back-end (non-encoded ;) )
if(ChunkHeader->UnusedBytes & 0x80)
  RtlpLowFragHeapFree
else
  BackEndHeapFree
'''
def _HEAP_getChunks(self, mappings):
  #for entry_addr,size in self.getSegmentList(mappings):
  #  yield (entry_addr,size)
  return self.getSegmentList(mappings)

_HEAP.getChunks = _HEAP_getChunks


def _HEAP_getFrontendChunks(self, mappings):
  ''' windows xp ?
    the list of chunks from the frontend are deleted from the segment chunk list. 
    
    Functionnaly, (page 28) LFH_HEAP should be fetched by HEAP_BUCKET calcul
    
  '''
  res = list()
  all_free = list()
  all_committed = list()
  log.debug('_HEAP_getFrontendChunks')
  if self.FrontEndHeapType == 1: # windows XP per default
    ptr = self.FrontEndHeap
    ## TODO delete this ptr from the heap-segment entries chunks
    for x in range(128):
      log.debug('finding lookaside %d at @%x'%(x, ptr))
      m = mappings.getMmapForAddr(ptr)
      st = m.readStruct( ptr, _HEAP_LOOKASIDE)
      # load members on self.FrontEndHeap car c'est un void *
      for free in st.iterateList('ListHead'): # single link list.
        ## TODO delete this free from the heap-segment entries chunks
        log.debug('free')
        res.append( free ) #???
        pass
      ptr += ctypes.sizeof(_HEAP_LOOKASIDE)
  elif self.FrontEndHeapType == 2: # win7 per default
    ptr = self.FrontEndHeap
    log.debug('finding frontend at @%x'%(ptr))
    m = mappings.getMmapForAddr(ptr)
    st = m.readStruct( ptr, _LFH_HEAP)
    # LFH is a big chunk allocated by the backend allocator, called subsegment
    # but rechopped as small chunks of a heapbin.
    # Active subsegment hold that big chunk.
    #
    #
    # load members on self.FrontEndHeap car c'est un void *
    if not st.loadMembers(mappings, 10):
      log.error('Error on loading frontend')
      raise model.NotValid('Frontend load at @%x is not valid'%(ptr))
    
    #log.debug(st.LocalData[0].toString())
    #
    for sinfo in st.LocalData[0].SegmentInfo: #### 128 _HEAP_LOCAL_SEGMENT_INFO
      # TODO , what about ActiveSubsegment ?
      for items_ptr in sinfo.CachedItems: # 16 caches items max
        items_addr = utils.getaddress(items_ptr)
        if not bool(items_addr):
          #log.debug('NULL pointer items')
          continue
        m = mappings.getMmapForAddr(items_addr)
        subsegment = m.readStruct( items_addr, _HEAP_SUBSEGMENT)
        #log.debug(subsegment)
        ## TODO current subsegment.SFreeListEntry is on error at some depth.
        ## bad pointer value on the second subsegment
        chunks = subsegment.get_userblocks()
        free = subsegment.get_freeblocks()
        committed = set(chunks) - set(free)
        all_free.extend(free)
        all_committed.extend( committed ) 
        log.debug('subseg: 0x%0.8x, commit: %d chunks free: %d chunks'%(items_addr, len(committed), len(free) ))
  else:
    #print 'FrontEndHeapType == %d'%(self.FrontEndHeapType)
    #raise StopIteration
    pass
  return all_committed, all_free
  
_HEAP.getFrontendChunks = _HEAP_getFrontendChunks


def _HEAP_SUBSEGMENT_get_userblocks(self):
  '''
  AggregateExchg contains info on userblocks, number left, depth
  
  '''
  userblocks_addr = utils.getaddress(self.UserBlocks)
  if not bool(userblocks_addr):
    log.debug('Userblocks is null')
    return []
  # its basically an array of self.BlockCount blocks of self.BlockSie*8 bytes.
  log.debug('fetching %d blocks of %d bytes'%(self.BlockCount, self.BlockSize*8))
  # UserBlocks points to _HEAP_USERDATA_HEADER. Real user data blocks will starts after sizeof( _HEAP_USERDATA_HEADER ) = 0x10
  # each chunk starts with a 8 byte header + n user-writeable data
  # user writable chunk starts with 2 bytes for next offset
  # basically, first committed block is first.
  # ( page 38 ) 
  userblocks = [ (userblocks_addr + 0x10 + self.BlockSize*8*i, self.BlockSize*8) for i in range(self.BlockCount)]
  #
  ## we need to substract non allocated blocks
  # self.AggregateExchg.Depth counts how many blocks are remaining free
  # if self.AggregateExchg.FreeEntryOffset == 0x2, there a are no commited blocks
  return userblocks 


def _HEAP_SUBSEGMENT_get_freeblocks(self):
  '''
  Use AggregateExchg.Depth and NextFreeoffset to fetch the head, then traverse the links
  '''
  userblocks_addr = utils.getaddress(self.UserBlocks)
  if not bool(userblocks_addr):
    return []
  if self.AggregateExchg.FreeEntryOffset == 0x2 :
    log.debug(' * FirstFreeOffset==0x2 Depth==%d'%(self.AggregateExchg.Depth))
  # self.AggregateExchg.Depth the size of UserBlock divided by the HeapBucket size
  # self.AggregateExchg.FreeEntryOffset starts at 0x2 (blocks), which means 0x10 bytes after UserBlocks
  # see Understanding LFH page 14
  # nextoffset of user data is at current + offset*8 + len(HEAP_ENTRY)
  freeblocks = [ (userblocks_addr + (self.AggregateExchg.FreeEntryOffset*8) + self.BlockSize*8*i, self.BlockSize*8) for i in range(self.AggregateExchg.Depth)]
  return freeblocks
  ###
    
  #ptr = utils.getaddress(self.AggregateExchg.FreeEntryOffset)
  #for i in range(self.AggregateExchg.Depth):
  #  free.append( userBlocks+ 8*ptr)
  #  ## ptr = m.readWord( userBlocks+ 8*ptr+8 ) ?????
  #return blocks 
  
  
  #free = []
  #ptr = subseg.FreeEntryOffset
  #subseg.depth.times { 
  #  free << (up + 8*ptr)
  #  ptr = @dbg.memory[up + 8*ptr + 8, 2].unpack('v')[0]
  #}
  #@foo ||= 0
  #@foo += 1
  #p @foo if @foo % 10 == 0#
  #
  #up += 0x10
  #list -= free
  #list.each { |p| @chunks[p+8] = bs*8 - (@cp.decode_c_struct('_HEAP_ENTRY', @dbg.memory, p).unusedbytes & 0x7f) }
  #end

_HEAP_SUBSEGMENT.get_userblocks = _HEAP_SUBSEGMENT_get_userblocks
_HEAP_SUBSEGMENT.get_freeblocks = _HEAP_SUBSEGMENT_get_freeblocks

#### HEAP_UCR_DESCRIPTOR
#_HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
#_HEAP_UCR_DESCRIPTOR._listHead_ = [  ('SegmentEntry', _HEAP_SEGMENT, 'SegmentListEntry'),  ]


#### _HEAP_LOCAL_SEGMENT_INFO
# _HEAP_LOCAL_SEGMENT_INFO.LocalData should be a pointer, but the values are small ints ?
# _HEAP_LOCAL_SEGMENT_INFO.LocalData == 0x3 ?
_HEAP_LOCAL_SEGMENT_INFO.expectedValues = {
  'LocalData': utils.IgnoreMember,
}



## TODO current subsegment.SFreeListEntry is on error at some depth.
## bad pointer value on the second subsegment
_HEAP_SUBSEGMENT.expectedValues = {
  'SFreeListEntry': utils.IgnoreMember,
}








def _HEAP_getFreeLists_by_blocksindex(self, mappings):
  ''' Understanding_the_LFH.pdf page 21 
  Not Implemented yet
  '''
  freeList = []
  # 128 blocks
  start = ctypes.addressof(self.BlocksIndex) 
  bi_addr = utils.getaddress(self.BlocksIndex)
  # enumerate BlocksIndex recursively on ExtendedLookup param
  while bi_addr != 0:
    log.debug('BLocksIndex is at %x'%(bi_addr))
    m = mappings.getMmapForAddr(bi_addr)
    bi = m.readStruct( bi_addr, _HEAP_LIST_LOOKUP)
    '''
      ('ExtendedLookup', POINTER(_HEAP_LIST_LOOKUP)),
      ('ArraySize', __uint32_t),
      ('ExtraItem', __uint32_t),
      ('ItemCount', __uint32_t),
      ('OutOfRangeItems', __uint32_t),
      ('BaseIndex', __uint32_t),
      ('ListHead', POINTER(_LIST_ENTRY)),
      ('ListsInUseUlong', POINTER(__uint32_t)),
      ('ListHints', POINTER(POINTER(_LIST_ENTRY))),
    '''
    log.debug('ArraySize is %d'%(bi.ArraySize))    
    log.debug('BlocksIndex: %s'%(bi.toString()))    
    hints_addr = utils.getaddress(bi.ListHints)
    log.debug('ListHints is pointing to %x'%(hints_addr))
    extlookup_addr = utils.getaddress(bi.ExtendedLookup)
    log.debug('ExtendedLookup is pointing to %x'%(extlookup_addr))
    if extlookup_addr == 0:
      ''' all chunks of size greater than or equal to BlocksIndex->ArraySize - 1 will 
      be stored in ascending order in FreeList[ArraySize-BaseIndex – 1] '''
      log.debug('Free chunks >= %d stored at FreeList[ArraySize(%d)-BaseIndex(%d) – 1]'%(bi.ArraySize-1, bi.ArraySize, bi.BaseIndex))
      #raise NotImplementedError()
    log.debug('-'*80)
    bi_addr = extlookup_addr
  # 
  raise NotImplementedError('NOT FINISHED')
  raise StopIteration


def _HEAP_ENTRY_decode(chunk_header, heap):
  '''returns a decoded copy '''
  #N11_HEAP_ENTRY3DOT_13DOT_2E()
  chunk_len = ctypes.sizeof(N11_HEAP_ENTRY3DOT_13DOT_2E)
  chunk_header_decoded = (N11_HEAP_ENTRY3DOT_13DOT_2E).from_buffer_copy(chunk_header)
  working_array = (ctypes.c_ubyte*chunk_len).from_buffer(chunk_header_decoded)
  encoding_array = (ctypes.c_ubyte*chunk_len).from_buffer_copy(heap.Encoding)
  # check if (heap.Encoding & working_array)
  s = 0
  for i in range(chunk_len):
    s += working_array[i] & encoding_array[i]
  #if s == 0: #DEBUG TODO
  #  print 'NOT ENCODED !!!',hex(ctypes.addressof(heap))
  #  return chunk_header
  for i in range(chunk_len):
    working_array[i] ^= encoding_array[i]
  return chunk_header_decoded

_HEAP_ENTRY.decode = _HEAP_ENTRY_decode
def _get_chunk(mappings, heap, entry_addr):
  from haystack.model import keepRef
  m = mappings.getMmapForAddr(entry_addr)
  chunk_header = m.readStruct( entry_addr, _HEAP_ENTRY)
  keepRef( chunk_header, _HEAP_ENTRY, entry_addr)
  chunk_header._orig_addr_ = entry_addr
  return chunk_header

def _HEAP_getFreeLists(self, mappings):
  ''' Understanding_the_LFH.pdf page 18 ++
  We iterate on _HEAP.FreeLists to get ALL free blocks.
  
  @returns freeblock_addr : the address of the _HEAP_ENTRY (chunk header)
           size           : the size of the free chunk + _HEAP_ENTRY header size, in blocks.
  '''
  res = list()
  sentinel = self._orig_address_ + 0xc4 # utils.offsetof(_HEAP, 'FreeLists')
  # FIXME - should be 
  ## for freeblock in self.iterateListField( mappings, 'FreeLists'):
  for freeblock_addr in self.FreeLists._iterateList( mappings):
    if freeblock_addr == sentinel:
      continue
    m = mappings.getMmapForAddr(freeblock_addr)
    freeblock = m.readStruct( freeblock_addr, _LIST_ENTRY)
    blink_value = utils.getaddress(freeblock.BLink)
    if ( blink_value & 1): # points to _HEAP_BUCKET +1
      log.warning('This freeblock BLink point to _HEAP_BUCKET at %x'%(blink_value))
    # its then a HEAP_ENTRY.. 
    #chunk_header = m.readStruct( freeblock_addr - 2*Config.WORDSIZE, _HEAP_ENTRY)
    chunk_header = m.readStruct( freeblock_addr - 2*Config.WORDSIZE, N11_HEAP_ENTRY3DOT_13DOT_2E) # Union stuff
    if self.EncodeFlagMask:
      log.debug('EncodeFlagMask is set on the HEAP. decoding is needed.')
      chunk_header = _HEAP_ENTRY_decode(chunk_header, self)
    #log.debug('chunk_header: %s'%(chunk_header.toString()))
    res.append( (freeblock_addr, chunk_header.Size ))# size = header + freespace
  return res
  

_HEAP.getFreeLists = _HEAP_getFreeLists

def _HEAP_getFreeListsWinXP(self, mappings):
  ''' Understanding_the_LFH.pdf page 17 '''
  freeList = []
  # 128 blocks
  start = ctypes.addressof(self.FreeLists) # sentinel value
  logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
  for freeBlock in self.FreeLists._iterateList( mappings):
    # try to get the size
    sizeaddr = freeBlock - Config.WORDSIZE
    memoryMap = utils.is_valid_address_value( sizeaddr, mappings)
    if memoryMap == False:
      raise ValueError('the link of this linked list has a bad value')
    val = memoryMap.readWord( sizeaddr)
    log.debug('\t - freeblock @%0.8x size:%d'%(freeBlock, val))
    yield freeBlock
  #free_chain = [freeBlock for freeBlock in self.iterateListField( mappings, 'FreeLists')]
  logging.getLogger('listmodel').setLevel(level=logging.INFO)

  raise StopIteration




########## _LIST_ENTRY

from haystack import listmodel
listmodel.declare_double_linked_list_type(_LIST_ENTRY, 'FLink', 'BLink')









