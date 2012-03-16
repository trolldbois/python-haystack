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
  print ' ********* _SLIST_HEADER_loadMembers'
  
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

_LIST_ENTRY.loadMembers = _LIST_ENTRY_loadMembers

"""
'SegmentListEntry' 
limit toString because first element is self.
"""
#def _attrToString(self,attr,field,attrtype,prefix):

##########

def _HEAP_SEGMENT_loadMembers(self, mappings, maxDepth):
  ''' '''
  print ' **  reload First entry and Last valid entry', hex(ctypes.addressof(self.FirstEntry)), hex(ctypes.addressof(self.LastValidEntry))
  
  # Cast first element to Union structure
  attr_obj_address = getaddress(self.FirstEntry)
  if not bool(self.FirstEntry):
    log.debug('FirstEntry has a Null pointer Flink')
    return True
  memoryMap = is_valid_address_value( attr_obj_address, mappings)
  if not memoryMap:
    print 'not memorymap', hex(attr_obj_address), hex(ctypes.addressof(self.FirstEntry))
    return False

  # Cast to type: HEAP_ENTRY
  # _0 N11_HEAP_ENTRY3DOT_13DOT_2E
  # _1 N11_HEAP_ENTRY3DOT_13DOT_3E
  # _2 N11_HEAP_ENTRY3DOT_13DOT_5E
  # AgregateCode uint64_t

  aggcode = struct.unpack('Q', memoryMap.readBytes( attr_obj_address, ctypes.sizeof(ctypes.c_ulonglong)))[0]
  print '** AgregateCode uint64_t', hex(aggcode)
  contents = memoryMap.readStruct( attr_obj_address, N11_HEAP_ENTRY3DOT_13DOT_2E)
  print '** _0 2E ', contents.toString('')
  contents = memoryMap.readStruct( attr_obj_address, N11_HEAP_ENTRY3DOT_13DOT_3E)
  print '** _1 3E ', contents.toString('')
  contents = memoryMap.readStruct( attr_obj_address, N11_HEAP_ENTRY3DOT_13DOT_5E)
  print '** _2 5E ', contents.toString('')


  if not LoadableMembers.loadMembers(self, mappings, maxDepth):
    return False

  return True

_HEAP_SEGMENT.loadMembers = _HEAP_SEGMENT_loadMembers

