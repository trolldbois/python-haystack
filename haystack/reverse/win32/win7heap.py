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
from haystack.config import Config

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

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

## make a match

_HEAP_SEGMENT.expectedValued = {
  'SegmentSignature':[0xffeeffee],
}

_HEAP.expectedValues = {
  'Signature':[0xeeffeeff],
}


def _LIST_ENTRY_loadMembers(self, mappings, maxDepth):
  ''' ''' 
  if not self.isValid(mappings):
    log.debug('LIST_ENTRY tries to load members when its not validated')
    return False
  # Cast first element to _SLIST_HEADER
  attr_obj_address = getaddress(self.FLink)
  if not bool(self.FLink):
    log.debug('List_entry has a Null pointer Flink')
    return True
  memoryMap = is_valid_address_value( attr_obj_address, mappings)
  contents = memoryMap.readStruct( attr_obj_address, _SLIST_HEADER)
  log.debug('contents acquired %d'%ctypes.sizeof(contents))
  #self.d.contents=BN_ULONG.from_address(ctypes.addressof(contents))
  #self.d=ctypes.cast(contents, ctypes.POINTER(BN_ULONG) ) 
  print ' ********* ', contents.toString()
  return True

#def BIGNUM_isValid(self,mappings):
#  if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
#    return False
#  return LoadableMembers.isValid(self,mappings)

#_LIST_ENTRY.loadMembers = _LIST_ENTRY_loadMembers

"""
'SegmentListEntry' 
limit toString because first element is self.
"""
#def _attrToString(self,attr,field,attrtype,prefix):

##########

def _HEAP_SEGMENT_loadMembers(self, mappings, maxDepth):
  ''' '''
  ## TODO load/walk links in UCRSegmentList as _HEAP_UCR_DESCRIPTOR
  ## first two pointers are flink, blink list double pointers.
  ## TODO pyobj
  
  flink, blink = loadListEntries(self, mappings, 'UCRSegmentList', _HEAP_UCR_DESCRIPTOR, maxDepth )

  if not LoadableMembers.loadMembers(self, mappings, maxDepth):
    return False
  # leak 2 list_entry of allocations ?
  
  self.UCRSegmentList.FLink.contents = _LIST_ENTRY.from_address( flink )
  self.UCRSegmentList.BLink.contents = _LIST_ENTRY.from_address( blink )

  return True

_HEAP_SEGMENT.loadMembers = _HEAP_SEGMENT_loadMembers

def loadListEntries(self, mappings, fieldname, structType, maxDepth):
  ''' LIST_ENTRY == struct 2 pointers 
  we need to force allocation in local space of a list of structType size, 
  instead of just the list_entry size.
  
  a) load first element as structType.
  b) delegate loadMembers to first element
  '''
  head = getattr(self, fieldname)
  flink = getaddress(head.FLink)
  print hex(flink)
  blink = getaddress(head.BLink)
  if flink == blink:
    log.debug('Load LIST_ENTRY on %s, only 1 element'%(fieldname))
  
  links = []
  # load both links// both ways, BLink is expected to be loaded from cache
  for link, name in [(flink, 'FLink'), (blink, 'BLink')]:
    if not bool(link):
      log.warning('%s has a Null pointer %s'%(fieldname, name))
      return True
    memoryMap = is_valid_address_value( link, mappings)
    if memoryMap is False:
      raise ValueError('invalid address %s 0x%x, not in the mappings.'%(name, link))
    # use cache if possible, avoid loops.
    ref = model.getRef( structType, link)
    if ref:
      log.debug("%s.%s loading from references cache %s/0x%lx"%(fieldname, name, structType, link ))
      ##getattr(head, name).contents = _LIST_ENTRY.from_address( ctypes.addressof(ref) )
      links.append( ctypes.addressof(ref) )
      continue # goto Blink or finish
    else:
      st = memoryMap.readStruct( link, structType) # reallocate the right size
      model.keepRef(st, structType, link)
      # load the list entry
      if not st.loadMembers(mappings, maxDepth-1):
        raise ValueError
      # set the pointer
      ##getattr(head, name).contents = _LIST_ENTRY.from_address( ctypes.addressof(st) )
      links.append( ctypes.addressof(ref) )
  
  #print self.UCRSegmentList
  #raise IOError
  return links[0],links[1]


def _HEAP_UCR_DESCRIPTOR_loadMembers(self, mappings, maxDepth):

  flink, blink = loadListEntries(self, mappings, 'ListEntry', _HEAP_UCR_DESCRIPTOR, maxDepth-1 )

  if not LoadableMembers.loadMembers(self, mappings, maxDepth):
    return False

  print ' ****************8 '   
  # load list entries
  self.ListEntry.FLink.contents = _LIST_ENTRY.from_address( flink )
  self.ListEntry.BLink.contents = _LIST_ENTRY.from_address( blink )
  
  # load segment list
  ## ? self.loadListEntries(mappings, 'SegmentEntry', _HEAP_SEGMENT, maxDepth-1 )

  return True

    
_HEAP_UCR_DESCRIPTOR.loadMembers = _HEAP_UCR_DESCRIPTOR_loadMembers

