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


''' insure ctypes basic types are subverted '''
from haystack import model
from haystack import utils
from haystack.config import Config

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
  log.debug('_isValidAttr attrname : %s'%(attrname))
  if attrname == 'LastValidEntry':
    return True # ignore
  else:
    return super(_HEAP_SEGMENT,self)._isValidAttr(attr,attrname,attrtype,mappings)

_HEAP_SEGMENT._isValidAttr = _HEAP_SEGMENT_isValidAttr

def _HEAP_SEGMENT_loadMember(self,attr,attrname,attrtype,mappings, maxDepth):
  log.debug('_loadMember attrname : %s'%(attrname))
  if attrname == 'LastValidEntry':
    # isPointerType code.
    log.debug('try pointer, ignore it if bad pointer.')
    _attrname='_'+attrname
    _attrType=self.classRef[attrtype]
    attr_obj_address = utils.getaddress(attr)
    setattr(self,'__'+attrname,attr_obj_address)
    ####
    memoryMap = utils.is_valid_address( attr, mappings, _attrType)
    if(not memoryMap):
      log.debug("LastValidEntry out of mapping - 0x%lx - ignore "%(attr_obj_address ))
      return True
    from haystack.model import getRef, keepRef, delRef # TODO CLEAN
    ref=getRef(_attrType,attr_obj_address)
    if ref:
      log.debug("%s %s loading from references cache %s/0x%lx"%(attrname,attr,_attrType,attr_obj_address ))
      #DO NOT CHANGE STUFF SOUPID attr.contents = ref
      return True
    log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, memoryMap ))
    ##### Read the struct in memory and make a copy to play with.
    ### ERRROR attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address, _attrType ))
    contents=memoryMap.readStruct(attr_obj_address, _attrType )
    # save that validated and loaded ref and original addr so we dont need to recopy it later
    keepRef( contents, _attrType, attr_obj_address)
    log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr, attr_obj_address, (utils.getaddress(attr))   ))
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
}
_HEAP._listHead_ = [  ('SegmentList', _HEAP_SEGMENT, 'SegmentListEntry', -16 ),
                      ('VirtualAllocdBlocks', _HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8 )]
#HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
#SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
# you need to ignore the Head in the iterator...



def _HEAP_getSegmentList(self, mappings):
  ''' list all heap entries attached to one Heap structure. '''
  for segment in self.iterateListField( mappings, 'SegmentList'):
    log.debug( 'FirstEntry:@%x LastValidEntry:@%x'%( utils.getaddress(segment.FirstEntry), utils.getaddress(segment.LastValidEntry)) )
    skiplist = []
    for ucr in segment.iterateListField( mappings, 'UCRSegmentList'):
      skiplist.append( (ucr.Address, ucr.Size) )
      log.debug("UCR address:@%x size:%x"%(ucr.Address, ucr.Size))

    ptr = utils.getaddress(segment.FirstEntry)
    ptrend = utils.getaddress(segment.LastValidEntry) + _HEAP_SEGMENT.Entry.size
    skiplist = [ (ucr.Address, ucr.Size) for ucr in 
            segment.iterateListField(mappings, 'UCRSegmentList') 
              if (ucr.Address > ptr) and ( ucr.Address + ucr.Size < ptrend) ]
    skiplist.append( (ptrend, 1) )
    log.debug( 'skiplist = %s'%( ["@%x %x"%(a,s) for a,s in skiplist]) )
    skiplist.sort()
    for entry_addr, entry_size in skiplist:
      log.debug('Entry: @%x Size:%x'%(ptr, entry_addr-ptr) )
      entry = _HEAP_ENTRY.from_address(ptr) # XX DEBUG readStruct ?
      yield (ptr, entry_addr-ptr)
      ptr = entry_addr + entry_size
  raise StopIteration

_HEAP.getSegmentList = _HEAP_getSegmentList

def _HEAP_scan_heap_segment(self, mappings, entry_addr, size):
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
      log.debug('Found a chunk at @%x size %x'% (entry_addr+off+ _HEAP_SEGMENT.Entry.size, sz - (he.UnusedBytes ^ unused) ) )
      yield ( (entry_addr+off+ _HEAP_SEGMENT.Entry.size) , (sz - (he.UnusedBytes ^ unused)) )
    else:
      log.debug('(he.Flags ^ flags) & 1 != 1: %s'% ((he.Flags ^ flags) & 1) ) # HEAP_ENTRY_BUSY = 0x1
      bad+=1
    off += sz
  log.debug('Found %d allocated chunks and %d with bad flags'%(chunks, bad) )
  raise StopIteration

def _HEAP_getChunkInfo(self):
	if self.EncodeFlagMask != 0:
		return (self.Encoding.Size, self.Encoding.Flags, self.Encoding.UnusedBytes)
	else:
	  return (0,0,0)

_HEAP.scan_heap_segment = _HEAP_scan_heap_segment
_HEAP.getChunkInfo = _HEAP_getChunkInfo


def _HEAP_getChunks(self, mappings):
  for entry_addr,size in self.getSegmentList(mappings):
    for chunk in self.scan_heap_segment( mappings, entry_addr, size):
      yield chunk
  raise StopIteration

_HEAP.getChunks = _HEAP_getChunks


def _HEAP_getFrontendChunks(self, mappings):
  ''' windows xp ?
    the list of chunks from the frontend are deleted from the segment chunk list. 
  '''
  log.debug('_HEAP_getFrontendChunks')
  if self.FrontEndHeapType == 1: # windows XP per default
    ptr = self.FrontEndHeap
    ## TODO delete this ptr from the heap-segment entries chunks
    for x in range(128):
      log.debug('finding lookaside %d at @%x'%(x, ptr))
      m = mappings.getMmapForAddr(ptr)
      st = m.readStruct( ptr, _HEAP_LOOKASIDE)
      # TODO loadmembers on frontendHeapType car c'est un void *
      for free in st.iterateList('ListHead'): # single link list.
        ## TODO delete this free from the heap-segment entries chunks
        log.debug('free')
        yield( free ) #???
        pass
      ptr += ctypes.sizeof(_HEAP_LOOKASIDE)
  elif self.FrontEndHeapType == 2: # win7 per default
    ptr = self.FrontEndHeap
    log.debug('finding frontend at @%x'%(ptr))
    m = mappings.getMmapForAddr(ptr)
    st = m.readStruct( ptr, _LFH_HEAP)
    #print st
    # _HEAP_LOCAL_SEGMENT_INFO.LocalData == 0x3 ?
    # Probably, we should not try to load segments ...
    #
    #
    #
    #
    if not st.loadMembers(mappings, 10):
      log.error('Error on loading frontend')
      raise model.NotValid('Frontend load at @%x is not valid'%(ptr))
    #
    for sinfo in st.LocalData[0].SegmentInfo: #### ?????
      for items_ptr in sinfo.CachedItems: # make getCachedItems()
        items_addr = utils.getaddress(items_ptr)
        if not bool(items_addr):
          log.debug('NULL pointer items')
          continue
        log.debug('finding ITEMS at @%x'%(items_addr))
        m = mappings.getMmapForAddr(items_addr)
        subsegment = m.readStruct( items_addr, _HEAP_SUBSEGMENT)
        ## TODO current subsegment.SFreeListEntry is on error at some depth.
        ## bad pointer value on the second subsegment
        for b in scan_lfh_ss(subsegment):
          yield b
  else:
    #print 'FrontEndHeapType == %d'%(self.FrontEndHeapType)
    raise StopIteration

  
_HEAP.getFrontendChunks = _HEAP_getFrontendChunks


def scan_lfh_ss(subseg):
  ####
  #### TODO
  ####
  userBlocks = utils.getaddress(subseg.UserBlocks)
  if not bool(userBlocks):
    return []
  blocks = [ (userBlocks + 0x10 + subseg.BlockSize*8*i,subseg.BlockSize*8) for i in range(subseg.BlockCount)]
  #
  ## TODO me DELETE, i need size with each block
  return blocks 
  free = []
  ptr = utils.getaddress(subseg.AggregateExchg.FreeEntryOffset)
  for i in range(subseg.AggregateExchg.Depth):
    free.append( userBlocks+ 8*ptr)
    ## ptr = m.readWord( userBlocks+ 8*ptr+8 ) ?????
  return blocks 
  
  
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


########## _LIST_ENTRY

from haystack import listmodel
listmodel.declare_double_linked_list_type(_LIST_ENTRY, 'FLink', 'BLink')









