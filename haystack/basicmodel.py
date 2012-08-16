#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module is the main aspect of haystack.
This specific plugin handles badics types.

'''

import ctypes
import logging
import numbers
import sys

from haystack.utils import *
from haystack.model import hasRef, getRef, keepRef, delRef, get_subtype, CString, getRefByAddr

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('basicmodel')

class LoadableMembers(object): 
  ''' 
  This is the main class, to be inherited by all ctypes structure.
  It adds a generic validaiton framework, based on simple assertion, 
  and on more complex constraint on members values.
    
  '''
  expectedValues=dict() # contraints on values TODO rename _expectedValues_
  def getFields(self):
    '''     Iterate over the fields and types of this structure, including inherited ones.'''
    return type(self).getFields()
  
  @classmethod
  def getFieldType(cls, fieldname):
    ''' return a members type'''
    ret= [(n,fieldtype) for n, fieldtype in cls.getFields() if n == fieldname]
    if len(ret) != 1:
      raise TypeError('No such field name %s in %s'%(fieldname, cls))
    return ret[0][1]
  
  @classmethod
  def getFields(cls):
    mro = cls.mro()[:-3] # cut Structure, _CData and object
    mro.reverse()
    me = mro.pop(-1)
    for typ in mro: # firsts are first, cls is in here in [-1]
      if not hasattr(typ, '_fields_'):
        continue
      for name,vtyp in typ.getFields():
        #yield ('%s_%s'%(typ.__name__, name), vtyp)
        yield (name, vtyp)
    # print mines.
    for f in me._fields_:
      yield (f[0],f[1])
    
    raise StopIteration

  def isValid(self,mappings):
    ''' 
    Checks if each members has coherent data 

    For each Field, check on of the three case, 
      a) basic types (check for expectedValues), 
        if field as some expected values in expectedValues
           check field value against expectedValues[fieldname]
           if False, return False, else continue
      
      b) struct(check isValid) 
        check if the inner struct isValid()
        if False, return False, else continue
      
      c) is an array , recurse validation
      
      d) Pointer(check valid_address or expectedValues is None == NULL )
        if field as some expected values in expectedValues 
          ( None or 0 ) are the only valid options to design NULL pointers
           check field getaddress() value against expectedValues[fieldname] // if NULL
              if True(address is NULL and it's a valid value), continue
           check getaddress against is_valid_address() 
              if False, return False, else continue
    '''
    valid = self._isValid(mappings)
    log.debug('-- <%s> isValid = %s'%(self.__class__.__name__,valid))
    return valid

  def _isValid(self,mappings):
    ''' real implementation.  check expectedValues first, then the other fields '''
    log.debug(' -- <%s> isValid --'%(self.__class__.__name__))
    _fieldsTuple = self.getFields()
    myfields=dict(_fieldsTuple)
    done=[]
    # check expectedValues first
    for attrname, expected in self.expectedValues.iteritems():
      done.append(attrname)
      log.debug(' +++ %s %s '%(attrname, expected))
      attrtype = myfields[attrname]
      attr=getattr(self,attrname)
      if expected is IgnoreMember:
        continue
      if not self._isValidAttr(attr,attrname,attrtype,mappings):
        return False
    # check the rest for validation
    todo = [ (name, typ) for name,typ in self.getFields() if name not in done ]
    for attrname,attrtype, in todo:
      attr=getattr(self,attrname)
      if not self._isValidAttr(attr,attrname,attrtype,mappings):
        return False
    # validation done
    return True
    
  def _isValidAttr(self,attr,attrname,attrtype,mappings):
    ''' Validation of a single member '''
    # a) 
    log.debug('valid: %s, %s'%(attrname, attrtype))
    if isBasicType(attrtype):
      if attrname in self.expectedValues:
        if attr not in self.expectedValues[attrname]:
          log.debug('basicType: %s %s %s bad value not in self.expectedValues[attrname]:'%(attrname,attrtype,repr(attr) ))
          return False
      log.debug('basicType: %s %s %s ok'%(attrname,attrtype,repr(attr) ))
      return True
    # b)
    elif isStructType(attrtype) or isUnionType(attrtype):
      ### do i need to load it first ? becaus it should be memcopied with the super()..
      if not attr.isValid(mappings):
        log.debug('structType: %s %s %s isValid FALSE'%(attrname,attrtype,repr(attr) ))
        return False
      log.debug('structType: %s %s %s isValid TRUE'%(attrname,attrtype,repr(attr) ))
      return True
    # c)
    elif isBasicTypeArray(attr):
      if attrname in self.expectedValues:
        if attr not in self.expectedValues[attrname]:
          log.debug('basicArray: %s %s %s bad value not in self.expectedValues[attrname]:'%(attrname,attrtype,repr(attr) ))
          return False
      log.debug('basicArray: %s is arraytype %s we decided it was valid',attrname,repr(attr))#
      return True
    elif isArrayType(attrtype):
      log.debug('array: %s is arraytype %s recurse validate'%(attrname,repr(attr)) )#
      attrLen=len(attr)
      if attrLen == 0:
        return True
      elType=type(attr[0])
      for i in range(0,attrLen):
        # FIXME BUG DOES NOT WORK - offsetof("%s[%d]") is called, and %s exists, not %s[%d]
        if not self._isValidAttr(attr[i], "%s[%d]"%(attrname,i), elType, mappings ):
          return False
      return True
    # d)
    elif isCStringPointer(attrtype):
      myaddress=getaddress(attr.ptr)
      if attrname in self.expectedValues:
        # test if NULL is an option
        if not bool(myaddress) :
          if not ( (None in self.expectedValues[attrname]) or
                   (0 in self.expectedValues[attrname]) ):
            log.debug('str: %s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
            return False
          log.debug('str: %s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
          return True
      if (myaddress != 0) and ( not is_valid_address_value( myaddress, mappings) )   :
        log.debug('str: %s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,myaddress))
        return False
      log.debug('str: %s %s %s is at 0x%lx OK'%(attrname,attrtype,repr(attr),myaddress ))
      return True
    # e) 
    elif isPointerType(attrtype):
      if attrname in self.expectedValues:
        # test if NULL is an option
        log.debug('isPointerType: bool(attr):%s attr:%s'%(bool(attr), attr))
        if not bool(attr):
          if not ( (None in self.expectedValues[attrname]) or
                   (0 in self.expectedValues[attrname]) ):
            log.debug('ptr: %s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
            return False
          log.debug('ptr: %s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
          return True
      # all case, 
      _attrType=None
      if isVoidPointerType(attrtype) or isFunctionType(attrtype):
        log.debug('Its a simple type. Checking mappings only.')
        if getaddress(attr) != 0 and not is_valid_address_value( attr, mappings): # NULL can be accepted
          log.debug('voidptr: %s %s %s 0x%lx INVALID simple pointer'%(attrname,attrtype, repr(attr) ,getaddress(attr)))
          return False
      else:
        # test valid address mapping
        _attrType = get_subtype(attrtype)
      #log.debug(" ihave decided on pointed attrType to be %s"%(_attrType))
      if ( not is_valid_address( attr, mappings, _attrType) ) and (getaddress(attr) != 0):
        log.debug('ptr: %s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,getaddress(attr)))
        return False
      # null is accepted by default 
      log.debug('ptr: name:%s repr:%s getaddress:0x%lx OK'%(attrname,repr(attr) ,getaddress(attr)))
      return True
    # ?
    #if isUnionType(attrtype):
    #  #log.warning('Union are not validated , yet ')
    #  return True
    log.error('What type are You ?: %s/%s'%(attrname,attrtype))
    return True

  def _isLoadableMember(self, attr, attrname, attrtype):
    '''
      Check if the member is loadable.
      A c_void_p cannot be load generically, You have to take care of that.
    '''
    #attrtype=type(attr)
    #and ( attrtype in self.classRef) 
    return ( (bool(attr) and (isPointerStructType(attrtype) or isPointerUnionType(attrtype) ) ) or
            #not isFunctionType(attrtype) and not ) or
              isStructType(attrtype)  or isCStringPointer(attrtype) or
              (isArrayType(attrtype) and not isBasicTypeArray(attr) ) ) # should we iterate on Basictypes ? no

  def loadMembers(self, mappings, maxDepth):
    ''' 
    The validity of the memebrs will be assessed.
    Each members that can be ( structures, pointers), will be evaluated for validity and loaded recursively.
    
    :param mappings: list of memoryMappings for the process.
    :param maxDepth: limitation of depth after which the loading/validation will stop and return results.

    @returns True if everything has been loaded, False if something went wrong. 
    '''
    if maxDepth == 0:
      log.debug('Maximum depth reach. Not loading any deeper members.')
      log.debug('Struct partially LOADED. %s not loaded'%(self.__class__.__name__))
      return True
    maxDepth-=1
    if not self.isValid(mappings):
      return False
    log.debug('- <%s> do loadMembers -'%(self.__class__.__name__))
    ## go through all members. if they are pointers AND not null AND in valid memorymapping AND a struct type, load them as struct pointers
    for attrname,attrtype in self.getFields():
      attr=getattr(self,attrname)
      # shorcut ignores
      if attrname in self.expectedValues:
        # shortcut
        if self.expectedValues[attrname] is IgnoreMember:
          # make an new empty ctypes
          #setattr(self, attrname, attrtype())
          pass
          ### we DO NOT WANT to modify read-only data
          return True      
      try:
        if not self._loadMember(attr,attrname,attrtype,mappings, maxDepth):
          return False
      except ValueError, e:
        log.error( 'maxDepth was %d'% maxDepth)
        raise #

    log.debug('- <%s> END loadMembers -'%(self.__class__.__name__))
    return True
    
  def _loadMember(self,attr,attrname,attrtype,mappings, maxDepth):
    # skip static basic data members
    if not self._isLoadableMember(attr, attrname, attrtype):
      log.debug("%s %s not loadable  bool(attr) = %s"%(attrname,attrtype, bool(attr)) )
      return True
    # load it, fields are valid
    elif isStructType(attrtype) or isUnionType(attrtype): # DEBUG TEST
      offset = offsetof(type(self),attrname)
      log.debug('st: %s %s is STRUCT at @%x'%(attrname,attrtype, self._orig_address_ + offset) )
      # TODO pydoc for impl.
      attr._orig_address_ = self._orig_address_ + offset
      if not attr.loadMembers(mappings, maxDepth+1):
        log.debug("st: %s %s not valid, erreur while loading inner struct "%(attrname,attrtype) )
        return False
      log.debug("st: %s %s inner struct LOADED "%(attrname,attrtype) )
      return True
    #elif isUnionType(attrtype):
    #  offset = offsetof(type(self),attrname)
    #  log.debug('st: %s %s is UNION at @%x'%(attrname,attrtype, self._orig_address_ + offset) )
    #  # TODO pydoc for impl.
    #  attr._orig_address_ = self._orig_address_ + offset
    #  return True
    # maybe an array
    elif isBasicTypeArray(attr):
      return True
    if isArrayType(attrtype):
      log.debug('a: %s is arraytype %s recurse load'%(attrname,repr(attr)) )#
      attrLen=len(attr)
      if attrLen == 0:
        return True
      elType=type(attr[0])
      for i in range(0,attrLen):
        # FIXME BUG DOES NOT WORK - offsetof("%s[%d]") is called, and %s exists, not %s[%d]
        #if not self._loadMember(attr[i], "%s[%d]"%(attrname,i), elType, mappings, maxDepth):
        if not self._loadMember(attr[i], attrname, elType, mappings, maxDepth):
          return False
      return True
    # we have PointerType here . Basic or complex
    # exception cases
    if isCStringPointer(attrtype) : 
      # can't use basic c_char_p because we can't load in foreign memory
      attr_obj_address = getaddress(attr.ptr)
      #setattr(self,'__'+attrname,attr_obj_address)
      if not bool(attr_obj_address):
        log.debug('%s %s is a CString, the pointer is null (validation must have occurred earlier) '%(attrname, attr))
        return True
      memoryMap = is_valid_address_value(attr_obj_address, mappings)
      if not memoryMap :
        log.warning('Error on addr while fetching a CString. should not happen')
        return False
      MAX_SIZE=255
      
      ref = getRef(CString,attr_obj_address)
      if ref:
        log.debug("%s %s loading from references cache %s/0x%lx"%(attrname,attr,CString,attr_obj_address ))
        return True
      log.debug("%s %s is defined as a CString, loading from 0x%lx is_valid_address %s"%(
                      attrname,attr,attr_obj_address, is_valid_address(attr,mappings) ))
      txt,full = memoryMap.readCString(attr_obj_address, MAX_SIZE )
      if not full:
        log.warning('buffer size was too small for this CString')

      # that will SEGFAULT attr.string = txt - instead keepRef to String
      keepRef( txt, CString, attr_obj_address)
      log.debug('kept CString ref for "%s" at @%x'%(txt, attr_obj_address))
      return True
    elif isPointerType(attrtype): # not functionType, it's not loadable
      _attrType = get_subtype(attrtype)
      attr_obj_address=getaddress(attr)
      #setattr(self,'__'+attrname,attr_obj_address)
      ####
      # memcpy and save objet ref + pointer in attr
      # we know the field is considered valid, so if it's not in memory_space, we can ignore it
      memoryMap = is_valid_address( attr, mappings, _attrType)
      if(not memoryMap):
        # big BUG Badaboum, why did pointer changed validity/value ?
        log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr,attr_obj_address ))
        return True

      ref = getRef(_attrType,attr_obj_address) 
      if ref:
        log.debug("%s %s loading from references cache %s/0x%lx"%(attrname,attr,_attrType,attr_obj_address ))
        #DO NOT CHANGE STUFF SOUPID attr.contents = ref. attr.contents will SEGFAULT
        return True
      log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, memoryMap ))
      ##### Read the struct in memory and make a copy to play with.
      #### DO NOT COPY THE STRUCT, we have a working readStruct for that...
      ### ERRROR attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address, _attrType ))
      contents=memoryMap.readStruct(attr_obj_address, _attrType )
      # save that validated and loaded ref and original addr so we dont need to recopy it later
      keepRef( contents, _attrType, attr_obj_address)
      log.debug("keepRef %s.%s @%x"%(_attrType, attrname, attr_obj_address  ))
      log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr, attr_obj_address, (getaddress(attr))   ))
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
    #TATAFN
    return True
  
  def toString(self, prefix='', depth=10):
    ''' Returns a string formatted description of this Structure. 
    The returned string should be python-compatible...
    '''
    # TODO: use a ref table to stop loops on parsed instance, 
    #       depth kinda sux.
    if depth == 0 :
      return '# DEPTH LIMIT REACHED\n'
    if hasattr(self, '_orig_address_'):
      s="%s # <%s at @%x>\n"%(prefix, self.__class__.__name__, self._orig_address_)
    else:
      s="%s # <%s at @???>\n"%(prefix, self.__class__.__name__)
    #s="%s # <%s @%x>\n"%(prefix, self.__class__.__name__, self._orig_address_ )
    for field,typ in self.getFields():
      attr = getattr(self,field)
      s += self._attrToString(attr, field, typ, prefix, depth)
    return s
    
  def _attrToString(self,attr,field,attrtype,prefix, depth=-1):
    s=''
    if isStructType(attrtype):
      s=prefix+'"%s": {\t%s%s},\n'%(field, attr.toString(prefix+'\t', depth-1),prefix )  
      #print field, attrtype, s
    elif isFunctionType(attrtype):
      s=prefix+'"%s": 0x%lx, #(FIELD NOT LOADED: function type)\n'%(field, getaddress(attr) )   # only print address in target space
    elif isBasicTypeArray(attr): ## array of something else than int      
      #log.warning(field)
      s=prefix+'"%s": b%s,\n'%(field, repr(array2bytes(attr)) )  
      #s=prefix+'"%s" :['%(field)+','.join(["0x%lx"%(val) for val in attr ])+'],\n'
    elif isArrayType(attrtype): ## array of something else than int/byte
      # go through each elements, we hardly can make a array out of that...
      s=prefix+'"%s" :{'%(field)
      eltyp=type(attr[0])
      for i in range(0,len(attr)):
        s+=self._attrToString( attr[i], i, eltyp, '')
      s+='},\n'
      #s=prefix+'"%s" :['%(field)+','.join(["%s"%(val) for val in attr ])+'],\n'
    elif isPointerType(attrtype):
      if not bool(attr) :
        s=prefix+'"%s": 0x%lx,\n'%(field, getaddress(attr) )   # only print address/null
      elif isVoidPointerType(attrtype) :
        s=prefix+'"%s": 0x%lx, #(FELD NOT LOADED: void pointer) \n'%(field, attr )   # only print address/null
      elif not is_address_local(attr) :
        s=prefix+'"%s": 0x%lx, #(FIELD NOT LOADED)\n'%(field, getaddress(attr) )   # only print address in target space
      else:
        # we can read the pointers contents # if isBasicType(attr.contents): ?  # if isArrayType(attr.contents): ?
        #contents=attr.contents
        _attrType = get_subtype(attrtype)        
        contents = getRef(_attrType, getaddress(attr))
        if type(self) == type(contents):
          s=prefix+'"%s": { #(0x%lx) -> %s\n%s},\n'%(field, 
                          getaddress(attr), _attrType, prefix) # use struct printer
        elif isStructType(type(contents)): # do not enter in lists
          s=prefix+'"%s": { #(0x%lx) -> %s%s},\n'%(field, getaddress(attr), 
                          contents.toString(prefix+'\t', depth-1),prefix) # use struct printer
        elif isPointerType(type(contents)):
          s=prefix+'"%s": { #(0x%lx) -> %s%s},\n'%(field, getaddress(attr), 
                          self._attrToString(contents, None, None, prefix+'\t'), prefix ) # use struct printer
        else:
          s=prefix+'"%s": { #(0x%lx) -> %s\n%s},\n'%(field, getaddress(attr), 
                          contents, prefix) # use struct printer
    elif isCStringPointer(attrtype):
      s=prefix+'"%s": "%s" , #(CString)\n'%(field, getRef(CString, getaddress(attr.ptr)) )  
    elif isBasicType(attrtype): # basic, ctypes.* !Structure/pointer % CFunctionPointer?
      s=prefix+'"%s": %s, \n'%(field, repr(attr) )  
    elif isUnionType(attrtype): # UNION
      #s=prefix+'"%s": %s, # UNION DEFAULT repr\n'%(field, repr(attr) )  
      s=prefix+'"%s": { # UNION DEFAULT repr\t%s%s},\n'%(field, attr.toString(prefix+'\t', depth-1),prefix )  
    else: # wtf ? 
      s=prefix+'"%s": %s, # Unknown/bug DEFAULT repr\n'%(field, repr(attr) )  
    return s

  def __str__(self):
    #print type(self), isUnionType(type(self))
    if hasattr(self, '_orig_address_'):
      s="# <%s at @%x>\n"%(self.__class__.__name__, self._orig_address_)
    else:
      s="# <%s at @???>\n"%(self.__class__.__name__)
    for field,attrtype in self.getFields():
      attr=getattr(self,field)
      if isStructType(attrtype) or isUnionType(attrtype): # DEBUG TEST
        s+='%s (@0x%lx) : {\t%s}\n'%(field,ctypes.addressof(attr), attr )  
        #s+='%s (@0x%lx) : {\t%s}\n'%(field, attr._orig_address_, attr )  
      elif isFunctionType(attrtype):
        s+='%s (@0x%lx) : 0x%lx (FIELD NOT LOADED: function type)\n'%(field,ctypes.addressof(attr), getaddress(attr) )   # only print address in target space
      elif isBasicTypeArray(attr):
        try:
          s+='%s (@0x%lx) : %s\n'%(field,ctypes.addressof(attr), repr(array2bytes(attr)) )  
        except IndexError,e:
          log.error( 'error while reading %s %s'%(repr(attr),type(attr)) )
          
      elif isArrayType(attrtype): ## array of something else than int
        s+='%s (@0x%lx)  :['%(field, ctypes.addressof(attr),)+','.join(["%s"%(val) for val in attr ])+'],\n'
        continue
      elif isCStringPointer(attrtype):
        if not bool(attr) :
          s+='%s (@0x%lx) : 0x%lx\n'%(field,ctypes.addressof(attr), getaddress(attr.ptr) )   # only print address/null
        elif not is_address_local(attr) :
          s=prefix+'"%s": 0x%lx, #(FIELD NOT LOADED)\n'%(field, getaddress(attr) )   # only print address in target space
        else:
          s+='%s (@0x%lx) : %s (CString) \n'%(field,ctypes.addressof(attr), getRef(CString, getaddress(attr.ptr)))  
      elif isPointerType(attrtype) and not isVoidPointerType(attrtype): # bug with CString
        if not bool(attr) :
          s+='%s (@0x%lx) : 0x%lx\n'%(field, ctypes.addressof(attr),   getaddress(attr) )   # only print address/null
        elif not is_address_local(attr) :
          s+='%s (@0x%lx) : 0x%lx (FIELD NOT LOADED)\n'%(field, ctypes.addressof(attr), getaddress(attr) )   # only print address in target space
        else:
          _attrType=get_subtype(attrtype)
          contents = getRef(_attrType, getaddress(attr))
          if type(self) == type(contents): # do not recurse in lists
            s+='%s (@0x%lx) : (0x%lx) -> {%s}\n'%(field, ctypes.addressof(attr), getaddress(attr), repr(contents) ) # use struct printer
          else:
            s+='%s (@0x%lx) : (0x%lx) -> {%s}\n'%(field, ctypes.addressof(attr), getaddress(attr), contents) # use struct printer
      elif type(attr) is long or type(attr) is int:
        s+='%s : %s\n'%(field, hex(attr) )  
      else:
        s+='%s : %s\n'%(field, repr(attr) )  
    return s

  def __repr__(self):
    if hasattr(self, '_orig_address_'):
      return "# <%s at @%x>\n"%(self.__class__.__name__, self._orig_address_)
    else:
      return "# <%s at @???>\n"%(self.__class__.__name__)
    
  def toPyObject(self):
    ''' 
    Returns a Plain Old python object as a perfect copy of this ctypes object.
    array would be lists, pointers, inner structures, and circular 
    reference should be handled nicely.
    '''
    # get self class.
    #log.debug("%s %s %s_py"%(self.__class__.__module__, sys.modules[self.__class__.__module__], self.__class__.__name__) )
    my_class = getattr(sys.modules[self.__class__.__module__],"%s_py"%(self.__class__.__name__) )
    my_self = my_class()
    #keep ref
    if hasRef(my_class, ctypes.addressof(self) ):
      return getRef(my_class, ctypes.addressof(self) )
    # we are saving us in a partially resolved state, to keep from loops.
    keepRef(my_self, my_class, ctypes.addressof(self) )
    log.debug('toPyObject before getFields %s 0x%x %d bytes'%(my_self, ctypes.addressof(self), ctypes.sizeof(self) ))
    
    log.debug('read from %x'%(ctypes.addressof(self)))
    data = (ctypes.c_ubyte*ctypes.sizeof(self)).from_address(ctypes.addressof(self))
    if not is_address_local(ctypes.pointer(data)):
      log.debug('addres is not local')
    #refs = getRefByAddr(ctypes.addressof(self))
    # TODO memoryleak here.
    #if len(refs) == 0:
    #  log.debug('No refs for self')
    #else:
    #  log.debug('%s'%( '\n'.join([ str(x) for x in refs]) ) )
    log.debug('concat to str')
    s = ''.join([ chr(data[i]) for i in range(0, ctypes.sizeof(self)) ])
    #log.debug('read %s '%( s ))
    
    
    
    for field,typ in self.getFields():
      log.debug('attr = getattr(self,field) %s,%s'%(field, typ))

      attr = getattr(self,field)
      log.debug('self._attrToPyObject(attr,field,typ) %s'%(typ))

      member = self._attrToPyObject(attr,field,typ)
      log.debug('setattr(my_self, field, member) %s,%s'%(field, typ))

      setattr(my_self, field, member)
      log.debug('loop %s'%(typ))
    # save the original type (me) and the field
    log.debug('setattr(my_self, _ctype_, type(self))  start %s'%(typ))
    setattr(my_self, '_ctype_', type(self))
    log.debug('setattr(my_self, _ctype_, type(self)) stop %s'%(typ))
    return my_self
    
  def _attrToPyObject(self,attr,field,attrtype):
    if isStructType(attrtype):
      log.debug('isStructType start %s'%(attrtype))
      obj=attr.toPyObject()
      log.debug('isStructType stop %s'%(attrtype))
    elif isUnionType(attrtype):
      log.debug('isUnionType start %s'%(attrtype))
      obj=attr.toPyObject()
      log.debug('isUnionType stop %s'%(attrtype))
    elif isBasicTypeArray(attr): ## array of basic types
      obj=array2bytes(attr)
    elif isArrayType(attrtype): ## array of something else than int/byte
      obj=[]
      eltyp=type(attr[0])
      for i in range(0,len(attr)):
        obj.append(self._attrToPyObject( attr[i], i, eltyp) )
    elif isFunctionType(attrtype):
      obj = repr(attr)
    elif isCStringPointer(attrtype):
      #obj = getRef(CString, getaddress(attr)).toString()
      obj = attr.toString()
    elif isPointerType(attrtype):
      if isVoidPointerType(attrtype):
        log.error('Void pointer - %s'%(field))
        obj='Void Pointer'
      elif isBasicTypeArray(attr):
        log.error('basic Type array - %s'%(field))
        obj='BasicType array'
      elif not bool(attr) :
        obj=(None,None)
      else:
        # get the cached Value of the LP.
        _subtype = get_subtype(attrtype)
        cache = getRef(_subtype, getaddress(attr) )
        if cache is not None:
          obj = self._attrToPyObject(cache, field, _subtype )
        elif isPointerBasicType(attrtype):
          log.error('Pointer to Basic type - %s'%(field))
          obj = 'Pointer to Basic type'
        else:
          log.error('LP structure for field:%s %s/%s not in cache %x'%(field, attrtype, get_subtype(attrtype), getaddress(attr) ) )
          #raise ValueError('LP structure for %s not in cache %s,%x'%(field, get_subtype(attrtype), getaddress(attr) ) )
          return (None,None)
    #    ####### any pointer should be in cache
    #    contents=attr.contents  # will SEGFAULT
    #    if isStructType(type(contents)) :
    #      attr_py_class = getattr(sys.modules[contents.__class__.__module__],"%s_py"%(contents.__class__.__name__) )
    #      cache = getRef(attr_py_class, getaddress(attr) )
    #      if cache:
    #        return cache
    #      #else:
    #      #  log.error('any LP struct should be in cache.')
    #      #  raise ValueError('LP structure not in cache %s'%(attr_py_class))
    #      obj=contents.toPyObject()
    #    elif isPointerType(type(contents)):
    #      obj=self._attrToPyObject(contents,None,None)
    #    else: # pointer vers autre chose, le repr() est le seul choix.
    #      #obj=repr(contents)
    #      obj=contents
    elif isBasicType(attrtype) and isCTypes(attr):
      obj = attr.value
    elif isinstance(attr, numbers.Number):
      obj = attr
    else:
      log.error('toPyObj default to return attr %s'%( type(attr) ))
      obj = attr
    return obj

def json_encode_pyobj(obj):
  if hasattr(obj, '_ctype_'):
    return obj.__dict__
  elif type(obj).__name__ == 'int':
    log.warning('found an int')
    return str(obj)
  else:
    return obj
    
class pyObj(object):
  ''' 
  Base class for a plain old python object.
  all haystack/ctypes classes will be translated in this format before pickling.
  
  Operations :
    - toString(self, prefix):  print a nicely formatted data structure
        :param prefix: str to insert before each line (\t after that)
    - findCtypes(self) : checks if a ctypes is to be found somewhere is the object.
                      Useful to check if the object can be pickled.
  '''
  def toString(self, prefix='',maxDepth=10):
    if maxDepth < 0:
      return '#(- not printed by Excessive recursion - )'
    s='{\n'
    for attrname,typ in self.__dict__.items():
      attr = getattr(self, attrname)
      s += "%s%s: %s\n"%( prefix, attrname, self._attrToString(attr, attrname, typ, prefix+'\t', maxDepth=maxDepth-1) )
    s+='}'
    return s

  def _attrToString(self, attr, attrname, typ, prefix, maxDepth):
    s=''
    if type(attr) is tuple or type(attr) is list:
      for i in xrange(0,len(attr)):
        s += '%s,'%(self._attrToString(attr[i], i ,None, prefix+'\t', maxDepth) )
      s = "[%s],"%(s)
    elif not hasattr(attr,'__dict__'):
      s = '%s,'%( repr(attr) )
    elif  isinstance( attr , pyObj):
      s = '%s,'%( attr.toString(prefix,maxDepth) )
    else:
      s = '%s,'%(repr(attr) )
    return s

  def __len__(self):
    return self._len_
    
  def findCtypes(self, cache=set()):
    ''' recurse on members to check for ctypes object. '''
    ret = False
    for attrname,attr in self.__dict__.items():
      if id(attr) in cache: # do not recurse in already parsed
        continue
      if attrname == '_ctype_' : # ignore _ctype_, it's a ctype class type, we know that.
        cache.add(id(attr))
        continue
      typ = type(attr)
      attr = getattr(self, attrname)
      log.debug('findCtypes on attr %s'% attrname)
      if self._attrFindCtypes(attr, attrname, typ, cache ):
        log.warning('Found a ctypes in %s'%(attrname))
        ret = True
    return ret

  def _attrFindCtypes(self, attr, attrname, typ, cache):
    ret = False
    cache.add(id(attr))
    if hasattr(attr, '_ctype_'): # a pyobj
      return attr.findCtypes(cache)
    elif type(attr) is tuple or type(attr) is list:
      for el in attr:
        if self._attrFindCtypes(el, 'element', None, cache):
          log.warning('Found a ctypes in array/tuple')
          return True
    elif isCTypes(attr):
      log.warning('Found a ctypes in self %s'%(attr))
      return True
    else: # int, long, str ...
      ret = False
    return ret

  def __iter__(self):
    ''' iterate on a instance's type's _fields_ members following the original type field order '''
    for k,typ in self._ctype_.getFields():
      v = getattr(self,k)
      yield (k,v,typ)
    pass

def findCtypesInPyObj(obj):
  ''' check function to help in unpickling errors correction '''
  ret = False
  if hasattr(obj, 'findCtypes'):
    if obj.findCtypes():
      log.warning('Found a ctypes in array/tuple')
      return True
  elif type(obj) is tuple or type(obj) is list:
    for el in obj:
      if findCtypesInPyObj(el):
        log.warning('Found a ctypes in array/tuple')
        return True
  elif isCTypes(obj):
    return True
  return False



