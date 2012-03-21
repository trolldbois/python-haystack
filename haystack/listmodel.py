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

log = logging.getLogger('listmodel')

class ListModel(object):
  _listMember_=[] # members that are the 2xpointer of same type linl
  _listHead_=[] # head structure of a linkedlist

  def loadListOfType(self, fieldname, mappings, structType, listFieldname, maxDepth):
    ''' load self.fieldname as a list of structType '''
    listfield = getattr(structType, listFieldname)
    offset = 0 - listfield.offset #- listfield.size 
    return self._loadListEntries(fieldname, mappings,  structType, maxDepth, offset)


  def loadListEntries(self, fieldname, mappings, maxDepth):
    ''' load self.fieldname as a list of self-typed '''
    listfield = getattr(type(self), fieldname)
    offset = 0 - listfield.offset #- listfield.size 
    return self._loadListEntries(fieldname, mappings, self.__class__ , maxDepth, offset)
    

  def _loadListEntries(self, fieldname, mappings,  structType, maxDepth, offset):
    ''' 
    we need to load the pointed entry as a valid struct at the right offset, 
    and parse it.
    '''
    head = getattr(self, fieldname)
    
    for entry in head.iterateList(mappings):
      link = entry + offset
      log.debug('got a element of list at %s 0x%x/0x%x offset:%d'%(fieldname, entry, link, offset))
      # use cache if possible, avoid loops.
      #XXX 
      from haystack import model
      ref = model.getRef( structType, link)
      if ref: # struct has already been loaded, bail out
        log.debug("%s loading from references cache %s/0x%lx"%(fieldname, structType, link ))
        continue # do not reload
      else:
        #  OFFSET read, specific to a LIST ENTRY model
        memoryMap = utils.is_valid_address_value( link, mappings, structType)
        if memoryMap is False:
          ## DEBUG
          #link -= 8
          #memoryMap = utils.is_valid_address_value( link, mappings, structType)
          #print memoryMap.readStruct( link, structType) 
          ## DEBUG
          log.error('error while validating address 0x%x type:%s @end:0x%x'%(link, 
                  structType.__name__, link+ctypes.sizeof(structType)) )
          log.error('self : %s , fieldname : %s'%(self.__class__.__name__, fieldname))
          raise ValueError('error while validating address 0x%x type:%s @end:0x%x'%(link, 
                  structType.__name__, link+ctypes.sizeof(structType)) )
        st = memoryMap.readStruct( link, structType) # point at the right offset
        model.keepRef(st, structType, link)
        # load the list entry structure members
        if not st.loadMembers(mappings, maxDepth-1):
          log.error('Error while loading members on %s'%(self.__class__.__name__))
          print st
          raise ValueError('error while loading members')
    
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
    
  def loadMembers(self, mappings, maxDepth):
    ''' 
    load basic types members, 
    then load list elements members recursively,
    then load list head elements members recursively.
    '''
    log.debug('-+ <%s> loadMembers +- @%x'%(self.__class__.__name__, self._orig_address_))

    #log.debug('load list elements at 0x%x'%(ctypes.addressof(self)))
    if not super(ListModel, self).loadMembers(mappings, maxDepth):
      return False

    print 'I HAVE an instance._orig_address_ %x'%self._orig_address_

    log.debug('load list elements members recursively on %s @%x '%(type(self).__name__, ctypes.addressof(self)))
    log.debug('listmember %s'%self.__class__._listMember_)
    for fieldname in self._listMember_:
      self.loadListEntries(fieldname, mappings, maxDepth )

    log.debug('load list head elements members recursively on %s'%(type(self).__name__))
    for fieldname,structType,structFieldname in self._listHead_:
      self.loadListOfType(fieldname, mappings, 
                          structType, structFieldname, maxDepth ) 
   
    log.debug('-+ <%s> loadMembers END +-'%(self.__class__.__name__))
    return True

  def __getFieldIterator(self, mappings, fieldname):
    if fieldname not in self._listMember_:
      raise ValueError('No such listMember field ')
    
    listfield = getattr(type(self), fieldname)
    offset = 0 - listfield.offset - listfield.size 
    
    done = []
    obj = self
    link = getattr(obj, fieldname).FLink # XXX
    while link not in done:

      done.append(link)

      if not bool(link):
        log.warning('%s has a Null pointer %s - NOT loading'%(fieldname, name))
        raise StopIteration

      link = link+offset
      # use cache if possible, avoid loops.
      from haystack import model
      st = model.getRef( structType, link)
      if st: # struct has already been loaded, bail out
        log.debug("%s.%s loading from references cache %s/0x%lx"%(fieldname, name, structType, link ))
        yield st
      else:
        #  OFFSET read, specific to a LIST ENTRY model
        memoryMap = utils.is_valid_address_value( link, mappings, structType)
        st = memoryMap.readStruct( link, structType) # point at the right offset
        model.keepRef(st, structType, link)
        yield st
      #
      link = getattr(st, fieldname).FLink # XXX

    raise StopIteration

  #def getListEntryIterator(self):
  #  ''' returns [(fieldname, iterator), .. ] '''
  #  for fieldname in self._listMember_:
  #    yield (fieldname, self.getFieldIterator(mappings, fieldname ) )
  

def declare_double_linked_list_type( structType, forward, backward):
  ''' declare a double linked list type.
  '''
  # test existence
  flinkType = getattr(structType, forward) 
  blinkType = getattr(structType, backward)
  d = dict(structType.getFields())
  flinkType = d[forward]
  blinkType = d[backward]
  if not utils.isPointerType(flinkType):
    raise TypeError('The %s field is not a pointer.'%(forward))
  if not utils.isPointerType(blinkType):
    raise TypeError('The %s field is not a pointer.'%(backward))

  def iterateList(self, mappings):
    ''' iterate forward, then backward, until null or duplicate '''    
    done = [0]
    obj = self
    for fieldname in [forward, backward]:
      link = getattr(obj, fieldname)
      addr = utils.getaddress(link)
      log.debug('iterateList got a <%s>/0x%x'%(link.__class__.__name__,addr))
      while addr not in done:
        done.append(addr)
        #print '\n%x '%(addr)
        memoryMap = utils.is_valid_address_value( addr, mappings, structType)
        if memoryMap == False:
          raise ValueError('the link of this linked list has a bad value')
        st = memoryMap.readStruct( addr, structType)
        yield addr
        # next
        link = getattr(st, fieldname)
        addr = utils.getaddress(link)

    raise StopIteration
  
  def loadMembers(self, mappings, depth):
    log.debug('- <%s> loadMembers return TRUE'%(structType.__name__))
    return True
    
  # set iterator on the list structure
  structType.iterateList = iterateList
  structType.loadMembers = loadMembers
  log.debug('%s has beed fitted with a list iterator self.iterateList(mappings)'%(structType))
  return
    

