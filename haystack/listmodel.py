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
from haystack import utils

import ctypes
import logging

log=logging.getLogger('listmodel')

class ListModel(object):
  _listMember_=[] # members that are the 2xpointer of same type linl
  _listHead_=[] # head structure of a linkedlist

  def loadListOfType(self, fieldname, mappings, structType, listFieldname, maxDepth):
    ''' load self.fieldname as a list of structType '''
    listfield = getattr(structType, listFieldname)
    offset = 0 - listfield.offset - listfield.size 
    return self._loadListEntries(fieldname, mappings,  structType, maxDepth, offset)


  def loadListEntries(self, fieldname, mappings, maxDepth):
    ''' load self.fieldname as a list of self-typed '''
    listfield = getattr(type(self), fieldname)
    offset = 0 - listfield.offset - listfield.size 
    return self._loadListEntries(fieldname, mappings, self.__class__ , maxDepth, offset)
    

  def _loadListEntries(self, fieldname, mappings,  structType, maxDepth, offset):
    ''' 
    we need to load the pointed entry as a valid struct at the right offset, 
    and parse it.
    
    LIST_ENTRY == struct 2 pointers 
    we need to force allocation in local space of a list of structType size, 
    instead of just the list_entry size.
    
    a) load first element as structType at offset - sizeof(_LIST_ENTRY).
        because user structs are allocated INSIDE list members
    b) delegate loadMembers to first element
    '''
    head = getattr(self, fieldname)
    flink = utils.getaddress(head.FLink) 
    blink = utils.getaddress(head.BLink) 
    print '--Listentry %s.%s 0x%x/0x%x 0x%x/0x%x with offset %d'%(structType.__name__, 
      fieldname, flink+offset, flink, blink+offset, blink, offset)
    if flink == blink:
      log.debug('Load LIST_ENTRY on %s, only 1 element'%(fieldname))

    # load both links// both ways, BLink is expected to be loaded from cache
    for link, name in [(flink, 'FLink'), (blink, 'BLink')]:
      if not bool(link):
        log.warning('%s has a Null pointer %s - NOT loading'%(fieldname, name))
        continue

      link = link+offset
      # validation of pointer values already have been made in isValid

      # use cache if possible, avoid loops.
      #XXX 
      from haystack import model
      ref = model.getRef( structType, link)
      if ref: # struct has already been loaded, bail out
        log.debug("%s.%s loading from references cache %s/0x%lx"%(fieldname, name, structType, link ))
        continue # goto Blink or finish
      else:
        #  OFFSET read, specific to a LIST ENTRY model
        memoryMap = utils.is_valid_address_value( link, mappings, structType)
  
        print hex(link), memoryMap, structType, ctypes.sizeof(structType)

        st = memoryMap.readStruct( link, structType) # point at the right offset
        model.keepRef(st, structType, link)
        print st
        # load the list entry structure members
        if not st.loadMembers(mappings, maxDepth-1):
          raise ValueError
    
    return True


  def _isLoadableMemberList(self, attr, attrname, attrtype):
    '''
      Check if the member is loadable.
      A c_void_p cannot be load generically, You have to take care of that.
    '''
    if not super(ListModel, self)._isLoadableMemberList(attr, attrname, attrtype) :
      return False
    if attrname in self._listMember_:
      return False
    return True
    
  def loadMembers(self,mappings, maxDepth):
    ''' 
    load basic types members, 
    then load list elements members recursively,
    then load list head elements members recursively.
    '''
    log.debug('load list elements at 0x%x'%(ctypes.addressof(self)))
    if not super(ListModel, self).loadMembers(mappings, maxDepth):
      return False

    log.debug('load list elements members recursively on %s'%(type(self).__name__))
    log.debug( 'listmember %s'%self.__class__._listMember_)
    for fieldname in self._listMember_:
      self.loadListEntries(fieldname, mappings, maxDepth )

    log.debug('load list head elements members recursively on %s'%(type(self).__name__))
    for fieldname,structType,structFieldname in self._listHead_:
      self.loadListOfType(fieldname, mappings, 
                          structType, structFieldname, maxDepth ) 
   
    return True
    
########## _reattach to class

#model.LoadableMembers.loadListOfType = loadListOfType
#model.LoadableMembers.loadListEntries = loadListEntries
#model.LoadableMembers.loadListPart2 = loadListPart2

#if ctypes.Structure.__name__ == 'Structure':
#  ctypes.Structure = LoadableMembersStructure
#if ctypes.Union.__name__ == 'Union':
#  ctypes.Union = LoadableMembersUnion



