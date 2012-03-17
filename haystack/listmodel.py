#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
"""
  Extension for list grammars.
  
"""
__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Beta"


''' insure ctypes basic types are subverted '''
from haystack import model

import logging

log=logging.getLogger('listmodel')

def loadListOfType(self, fieldname, mappings, structType, listFieldname, maxDepth):
  ''' load self.fieldname as a list of structType '''
  offset = model.offsetof( structType, listFieldname ) + ctypes.sizeof(_LIST_ENTRY)
  print structType, listFieldname, offset
  return _loadListEntries(self, fieldname, mappings,  structType, maxDepth, offset)


def loadListEntries(self, fieldname, mappings, maxDepth):
  ''' load self.fieldname as a list of self-typed '''
  offset = model.offsetof( type(self), fieldname ) + ctypes.sizeof(_LIST_ENTRY)
  print type(self), fieldname, offset
  return _loadListEntries(self, fieldname, mappings, self.__class__ , maxDepth, offset)
  

def _loadListEntries(self, fieldname, mappings,  structType, maxDepth, offset):
  ''' LIST_ENTRY == struct 2 pointers 
  we need to force allocation in local space of a list of structType size, 
  instead of just the list_entry size.
  
  a) load first element as structType at offset - sizeof(_LIST_ENTRY).
      because user structs are allocated INSIDE list members
  b) delegate loadMembers to first element
  '''
  head = getattr(self, fieldname)
  flink = getaddress(head.FLink)
  blink = getaddress(head.BLink)
  print '--Listentry %s.%s 0x%x 0x%x with offset %d'%(structType.__name__, fieldname, flink, blink, offset)
  if flink == blink:
    log.debug('Load LIST_ENTRY on %s, only 1 element'%(fieldname))
  links = []
  # load both links// both ways, BLink is expected to be loaded from cache
  for link, name in [(flink, 'FLink'), (blink, 'BLink')]:
    if not bool(link):
      log.warning('%s has a Null pointer %s'%(fieldname, name))
      links.append( link )
      continue
    memoryMap = is_valid_address_value( link, mappings)
    if memoryMap is False:
      raise ValueError('invalid address %s 0x%x, not in the mappings.'%(name, link))
    # use cache if possible, avoid loops.
    ref = model.getRef( structType, link)
    if ref:
      log.debug("%s.%s loading from references cache %s/0x%lx"%(fieldname, name, structType, link ))
      links.append( ctypes.addressof(ref) )
      continue # goto Blink or finish
    else:
      #  OFFSET read, specific to a LIST ENTRY model
      st = structType.from_buffer_copy(memoryMap.readStruct( link-offset, structType)) # reallocate the right size
      model.keepRef(st, structType, link)
      print st
      # load the list entry structure members
      if not st.loadMembers(mappings, maxDepth-1):
        raise ValueError
      # save the pointer
      links.append( ctypes.addressof(st) )
  
  return links[0],links[1]

def loadListPart2(self, fieldname, part1):
  ''' 
  Change the local allocated pointer values to the local pointers with proper
    sizes 
  '''
  flink, blink = part1
  field = getattr(self,fieldname)
  field.FLink.contents = _LIST_ENTRY.from_address( flink )
  field.BLink.contents = _LIST_ENTRY.from_address( blink )
  return

########## _reattach to class

model.LoadableMembers.loadListOfType = model.LoadableMembers_loadListOfType
model.LoadableMembers.loadListEntries = model.LoadableMembers_loadListEntries
model.LoadableMembers.loadListPart2 = model.LoadableMembers_loadListPart2




