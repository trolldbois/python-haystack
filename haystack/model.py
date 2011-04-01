#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes,os, types
from struct import pack,unpack
from memory_mapping import readProcessMappings
import logging
log=logging.getLogger('model')

#import copy
''' replace c_char_p '''
if ctypes.c_char_p.__name__ == 'c_char_p':
  ctypes.original_c_char_p = ctypes.c_char_p

''' keep orig class '''
if ctypes.Structure.__name__ == 'Structure':
  ctypes.original_Structure = ctypes.Structure

__refs = list()
__register = dict()

def keepRef(obj):
  ''' Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object, 
    they might be transient (if obj == somepointer.contents).'''
  __refs.append(obj)
  return

def register(klass):
  klass.classRef = __register
  __register[ctypes.POINTER(klass)] = klass
  return klass


''' returns if the address of the struct is in the mapping area
'''
def is_valid_address(obj,mappings, structType=None):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  # check for null pointers
  #print 'is_valid_address'
  addr=getaddress(obj)
  if addr == 0:
    return False
  return is_valid_address_value(addr,mappings,structType)

def is_valid_address_value(addr,mappings,structType=None):
  for m in mappings:
    if addr in m:
      # check if end of struct is ALSO in m
      if (structType is not None):
        s=ctypes.sizeof(structType)
        if (addr+s) not in m:
          return False
      return m
  return False

def is_address_local(obj, structType=None):
  ''' costly , checks if obj is mapped to local memory '''
  addr=getaddress(obj)
  if addr == 0:
    return False
  class P:
    pid=os.getpid()
  mappings= readProcessMappings(P())
  return is_valid_address(obj,mappings, structType)

''' returns the address of the struct
'''
def getaddress(obj):
  # check for null pointers
  #print 'getaddress'
  if bool(obj):
    if not hasattr(obj,'contents'):
      return 0
    #print 'get adressses is '
    return ctypes.addressof(obj.contents)
  else:
    #print 'object pointer is null'
    return 0  

''' MISSING
d 	double 	float 	8 	(4)
p 	char[] 	string 	  	 
'''
bytestr_fmt={
  'c_bool': '?',
  'c_char': 'c',
  'c_byte': 'b',
  'c_ubyte': 'B',
  'c_short': 'h',
  'c_ushort': 'H',
  'c_int': 'i', #c_int is c_long
  'c_uint': 'I',
  'int': 'i', 
  'c_long': 'l', #c_int is c_long
  'c_ulong': 'L',
  'long': 'q', 
  'c_longlong': 'q',
  'c_ulonglong': 'Q',
  'c_float': 'f', ## and double float ?
  'c_char_p': 's',
  'c_void_p': 'P'
  }
def array2bytes_(array, typ):
  arrayLen=len(array)
  if arrayLen == 0:
    return b''
  if typ not in bytestr_fmt:
    log.warning('Unknown ctypes to pack: %s'%(typ))
    return None
  fmt=bytestr_fmt[typ]
  sb=b''
  for el in array:
    sb+=pack(fmt, el)
  return sb

def array2bytes(array):
  if not isBasicTypeArrayType(array):
    return b'NOT-AN-BasicType-ARRAY'
  # BEURK
  typ='_'.join(type(array).__name__.split('_')[:2])
  return array2bytes_(array,typ)

def bytes2array(bytes, typ):
  typLen=ctypes.sizeof(typ)
  if len(bytes)%typLen != 0:
    raise ValueError('thoses bytes are not an array of %s'%(typ))
  arrayLen=len(bytes)/typLen
  array=(typ*arrayLen)()
  if arrayLen == 0:
    return array
  if typ.__name__ not in bytestr_fmt:
    log.warning('Unknown ctypes to pack: %s'%(typ))
    return None
  fmt=bytestr_fmt[typ.__name__]
  sb=b''
  for i in range(0,arrayLen):
    array[i]=unpack(fmt, bytes[typLen*i:typLen*(i+1)])[0]
  return array


def pointer2bytes(attr,nbElement):
  # attr is a pointer and we want to read elementSize of type(attr.contents))
  if not is_address_local(attr):
    return 'POINTER NOT LOCAL'
  firstElementAddr=getaddress(attr)
  array=(type(attr.contents)*nbElement).from_address(firstElementAddr)
  # we have an array type starting at attr.contents[0]
  return array2bytes(array)
    
def isBasicType(obj):
  return  (type(obj).__module__ in ['ctypes','_ctypes','__builtin__']) 

def isStructType(obj):
  ''' a struct is what WE have created '''
  #return isinstance(obj,LoadableMembers)
  return isinstance(obj, ctypes.Structure)
  # or use obj.classRef
  
def isPointerType(obj):
  if isBasicType(obj) or isStructType(obj):
    return False
  return type(obj).__class__.__name__== 'PointerType'

def isBasicTypeArrayType(obj):
  if isArrayType(obj):
    if isBasicType(obj[0]):
      return True
  return False

def isArrayType(obj):
  return type(obj).__class__.__name__=='ArrayType'

def isFunctionType(obj):
  return type(obj).__class__.__name__=='CFuncPtrType'

def isCStringPointer(obj):
  return obj.__class__.__name__ == 'CString'

def isUnionType(obj):
  return isinstance(obj,ctypes.Union) and not isCStringPointer(obj)


class IgnoreMember:
  def __contains__(self,obj):
    return True

class RangeValue:
  def __init__(self,low,high):
    self.low=low
    self.high=high
  def __contains__(self,obj):
    return self.low <= obj <= self.high
  def __eq__(self,obj):
    return self.low <= obj <= self.high

class NotNullComparable:
  def __contains__(self,obj):
    return bool(obj)
  def __eq__(self,obj):
    return bool(obj)

NotNull=NotNullComparable()

class CString(ctypes.Union):
  ''' ctypes.c_char_p can not be used for memory parsing. it tries to load the string itself '''
  _fields_=[
  ("string", ctypes.original_c_char_p),
  ("ptr", ctypes.POINTER(ctypes.c_ubyte) )
  ]
  def toString(self):
    if not bool(self.ptr):
      return "<NULLPTR>"
    return self.string
  pass



#debug
def printWhois(attr):
  print ' : isBasicType(attr): %s bool(attr): %s'%(isBasicType(attr) ,bool(attr)) 
  print ' : isCStringPointer(attr): %s isStructType(attr): %s'%(isCStringPointer(attr) ,isStructType(attr)) 
  print ' : isArrayType(attr): %s isBasicTypeArrayType(attr): %s'%(isArrayType(attr) ,isBasicTypeArrayType(attr)) 
  print ' : isPointerType(attr): %s type(attr) %s '%(isPointerType(attr),type(attr) ) 
  print ' : ',attr.__class__.__name__, type(attr)


class LoadableMembers(ctypes.Structure):
  ''' ctypes.POINTER types for automatic address space checks '''
  classRef=dict()
  expectedValues=dict()

  def isValid(self,mappings):
    '''  checks if each members has coherent data  '''
    valid = self._isValid(mappings)
    log.debug('%s isValid = %s'%(self.__class__.__name__,valid))
    return valid

  def _isValid(self,mappings):
    ''' For each Field, check on of the three case, 
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
    # precheck for quick unvalidation
    # myfields=dict(self._fields_)  ## some fields are initialised...
    _fieldsTuple = [ (f[0],f[1]) for f in self._fields_] 
    myfields=dict(_fieldsTuple)
    for attrname, expected in self.expectedValues.iteritems():
      attrtype = myfields[attrname]
      attr=getattr(self,attrname)
      if expected is IgnoreMember:
        continue
      if not self._isValidAttr(attr,attrname,attrtype,mappings):
        return False
    #if len(self.expectedValues) >0 :
    #  log.info('maybe valid . full validation follows validated :%s'%(self.expectedValues.keys()))    
    # normal check
    for attrname,attrtype, in _fieldsTuple:
      attr=getattr(self,attrname)
      # get expected values
      if attrname in self.expectedValues:
        # shortcut
        if self.expectedValues[attrname] is IgnoreMember:
          continue # oho ho
      # validate
      if not self._isValidAttr(attr,attrname,attrtype,mappings):
        return False
      #continue
    # loop done
    return True
    
  def _isValidAttr(self,attr,attrname,attrtype,mappings):
    # check this attr
    if attrname in [] :
      print 'Ivalid ',repr(self)
      printWhois(attr)
    # a) 
    if isBasicType(attr):
      if attrname in self.expectedValues:
        if attr not in self.expectedValues[attrname]:
          log.debug('%s %s %s bad value not in self.expectedValues[attrname]:'%(attrname,attrtype,repr(attr) ))
          return False
      log.debug('%s %s %s ok'%(attrname,attrtype,repr(attr) ))
      return True
    # b)
    if isStructType(attr):
      ### do i need to load it first ? becaus it should be memcopied with the super()..
      if not attr.isValid(mappings):
        log.debug('%s %s %s isValid FALSE'%(attrname,attrtype,repr(attr) ))
        return False
      log.debug('%s %s %s isValid TRUE'%(attrname,attrtype,repr(attr) ))
      return True
    # c)
    if isBasicTypeArrayType(attr):
      #log.info('%s is arraytype %s we decided it was valid',attrname,repr(attr))#
      return True
    if isArrayType(attr):
      log.debug('%s is arraytype %s recurse validate'%(attrname,repr(attr)) )#
      attrLen=len(attr)
      if attrLen == 0:
        return True
      elType=type(attr[0])
      for i in range(0,attrLen):
        if not self._isValidAttr(attr[i], "%s[%d]"%(attrname,i), elType, mappings ):
          return False
      return True
    # d)
    if isCStringPointer(attr):
      myaddress=getaddress(attr.ptr)
      if attrname in self.expectedValues:
        # test if NULL is an option
        if not bool(myaddress) :
          if not ( (None in self.expectedValues[attrname]) or
                   (0 in self.expectedValues[attrname]) ):
            log.debug('%s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
            return False
          log.debug('%s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
          return True
      if (myaddress != 0) and ( not is_valid_address_value( myaddress, mappings) )   :
        log.debug('%s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,myaddress))
        return False
      log.debug('%s %s %s is at 0x%lx OK'%(attrname,attrtype,repr(attr),myaddress ))
      return True
    # e) 
    if isPointerType(attr):
      #### try to debug mem
      setattr(self,attrname+'ContentAddress',getaddress(attr))
      ####
      if attrname in self.expectedValues:
        # test if NULL is an option
        if not bool(attr):
          if not ( (None in self.expectedValues[attrname]) or
                   (0 in self.expectedValues[attrname]) ):
            log.debug('%s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
            return False
          log.debug('%s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
          return True
      # all case, 
      _attrType=None
      if attrtype not in self.classRef:
        log.debug("I can't know the size of the basic type behind the %s pointer, it's a pointer to basic type")
        _attrType=None
      else:
        # test valid address mapping
        _attrType=self.classRef[attrtype]
      #log.debug(" ihave decided on pointed attrType to be %s"%(_attrType))
      if ( not is_valid_address( attr, mappings, _attrType) ) and (getaddress(attr) != 0):
        log.debug('%s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,getaddress(attr)))
        return False
      # null is accepted by default 
      log.debug('%s %s 0x%lx OK'%(attrname,repr(attr) ,getaddress(attr)))
      return True
    # ?
    if isUnionType(attr):
      #log.warning('Union are not validated , yet ')
      return True
    log.error('What type are You ?: %s'%attrname)
    return True

  def _isLoadableMember(self, attr):
    '''
      Un VoidPointer ne doit pas etre Loadable
    '''
    attrtype=type(attr)
    return ( (isPointerType(attr) and ( attrtype in self.classRef) and bool(attr) ) or
              isStructType(attr)  or isCStringPointer(attr) or
              (isArrayType(attr) and not isBasicTypeArrayType(attr) ) ) # should we iterate on Basictypes ? no

  def loadMembers(self, mappings, maxDepth):
    ''' 
    The validity of the memebrs will be assessed.
    Each members that can be ( structures, pointers), will be evaluated for validity and loaded recursively.
    
    @param mappings: list of memoryMappings for the process.
    @param maxDepth: limitation of depth after which the loading/validation will stop and return results.

    @returns True if everything has been loaded, False if something went wrong. 
    '''
    if maxDepth == 0:
      log.warning('Maximum depth reach. Not loading any deeper members.')
      log.warning('Struct partially LOADED. %s not loaded'%(self.__class__.__name__))
      return True
    maxDepth-=1
    log.debug('%s loadMembers'%(self.__class__.__name__))
    if not self.isValid(mappings):
      return False
    log.debug('%s do loadMembers ----------------'%(self.__class__.__name__))
    ## go through all members. if they are pointers AND not null AND in valid memorymapping AND a struct type, load them as struct pointers
    _fieldsTuple = [ (f[0],f[1]) for f in self._fields_] 
    for attrname,attrtype in _fieldsTuple:
      attr=getattr(self,attrname)
      # shorcut ignores
      if attrname in self.expectedValues:
        # shortcut
        if self.expectedValues[attrname] is IgnoreMember:
          # make an new empty ctypes
          setattr(self, attrname, attrtype())
          return True      
      try:
        if not self._loadMember(attr,attrname,attrtype,mappings, maxDepth):
          return False
      except ValueError, e:
        log.error( 'maxDepath was %d'% maxDepth)
        raise e

    log.debug('%s END loadMembers ----------------'%(self.__class__.__name__))
    return True
    
  def _loadMember(self,attr,attrname,attrtype,mappings, maxDepth):
    ### debug
    if attrname in []:
      #if True:
      print repr(self)
      printWhois(attr)
      print ' : _isLoadableMember() %s'%(self._isLoadableMember(attr) )
      print ' ********** 0x%lx ' % ctypes.addressof(attr)
      if bool(attr):
        print ' ********** 0x%lx ' % ctypes.addressof(attr.contents)
    # skip static basic data members
    if not self._isLoadableMember(attr):
      log.debug("%s %s not loadable  bool(attr) = %s"%(attrname,attrtype, bool(attr)) )
      return True
    # load it, fields are valid
    if isStructType(attr):
      log.debug('%s %s is STRUCT'%(attrname,attrtype) )
      if not attr.loadMembers(mappings, maxDepth+1):
        log.debug("%s %s not valid, erreur while loading inner struct "%(attrname,attrtype) )
        return False
      log.debug("%s %s inner struct LOADED "%(attrname,attrtype) )
      return True
    # maybe an array
    if isBasicTypeArrayType(attr):
      return True
    if isArrayType(attr):
      log.debug('%s is arraytype %s recurse load'%(attrname,repr(attr)) )#
      attrLen=len(attr)
      if attrLen == 0:
        return True
      elType=type(attr[0])
      for i in range(0,attrLen):
        if not self._loadMember(attr[i], "%s[%d]"%(attrname,i), elType, mappings, maxDepth):
          return False
      return True
    # we have PointerType here . Basic or complex
    # exception cases
    if isCStringPointer(attr) : 
      # can't use basic c_char_p because we can't load in foreign memory
      attr_obj_address = getaddress(attr.ptr)
      if not bool(attr_obj_address):
        log.debug('%s %s is a CString, the pointer is null (validation must have occurred earlier) '%(attrname, attr))
        return True
      memoryMap = is_valid_address_value(attr_obj_address, mappings)
      if not memoryMap :
        log.warning('Error on addr while fetching a CString. should not happen')
        return False
      setattr(self,'__'+attrname,attr_obj_address)
      MAX_SIZE=255
      log.debug("%s %s is defined as a CString, loading from 0x%lx is_valid_address %s"%(
                      attrname,attr,attr_obj_address, is_valid_address(attr,mappings) ))
      txt,full = memoryMap.readCString(attr_obj_address, MAX_SIZE )
      if not full:
        log.warning('buffer size was too small for this CString')
      attr.string = txt
      return True
    else:
      _attrname='_'+attrname
      _attrType=self.classRef[attrtype]
      attr_obj_address=getaddress(attr)
      setattr(self,'__'+attrname,attr_obj_address)
      ####
      previous=getattr(self,attrname+'ContentAddress')
      if attr_obj_address !=previous:
        log.warning('Change of pointer value between validation and loading... 0x%lx 0x%lx'%(previous,attr_obj_address))
      # memcpy and save objet ref + pointer in attr
      # we know the field is considered valid, so if it's not in memory_space, we can ignore it
      memoryMap = is_valid_address( attr, mappings, _attrType)
      if(not memoryMap):
        # big BUG Badaboum, why did pointer changed validity/value ?
        log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr,attr_obj_address ))
        return True
      log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, memoryMap ))
      ##### VALID INSTR.
      attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address, _attrType ))
      #####
      log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr,attr_obj_address, (getaddress(attr))   ))
      # recursive validation checks on new struct
      if not bool(attr):
        log.warning('Member %s is null after copy: %s'%(attrname,attr))
        return True
      # go and load the pointed struct members recursively
      if not attr.contents.loadMembers(mappings, maxDepth):
        log.debug('member %s was not loaded'%(attrname))
        return False
    #TATAFN
    return True
  
  def toString(self,prefix=''):
    ''' return a string formatted description of this Structure. '''
    s="%s # %s\n"%(prefix,repr(self) )
    _fieldsTuple = [ (f[0],f[1]) for f in self._fields_] 
    for field,typ in _fieldsTuple:
      attr=getattr(self,field)
      s+=self._attrToString(attr,field,typ,prefix)
    return s
    
  def _attrToString(self,attr,field,typ,prefix):
    s=''
    if isStructType(attr):
      s=prefix+'"%s": {\t%s%s},\n'%(field, attr.toString(prefix+'\t'),prefix )  
    #elif isBasicTypeArrayType(attr):
    #  #s=prefix+'"%s": %s,\n'%(field, array2bytes(attr) )  
    #  s='['+','.join(["%lx"%(val) for val in attr ])
    elif isBasicTypeArrayType(attr): ## array of something else than int
      s=prefix+'"%s": b%s,\n'%(field, repr(array2bytes(attr)) )  
      #s=prefix+'"%s" :['%(field)+','.join(["0x%lx"%(val) for val in attr ])+'],\n'
    elif isArrayType(attr): ## array of something else than int/byte
      # go through each elements, we hardly can make a array out of that...
      s=prefix+'"%s" :{'%(field)
      typ=type(attr[0])
      for i in range(0,len(attr)):
        s+=self._attrToString( attr[i], i, typ, '')
      s+='},\n'
      #s=prefix+'"%s" :['%(field)+','.join(["%s"%(val) for val in attr ])+'],\n'
    elif isPointerType(attr):
      if not bool(attr) :
        s=prefix+'"%s": 0x%lx,\n'%(field, getaddress(attr) )   # only print address/null
      elif not is_address_local(attr) :
        s=prefix+'"%s": 0x%lx, #(FIELD NOT LOADED)\n'%(field, getaddress(attr) )   # only print address in target space
      else:
        # we can read the pointers contents # if isBasicType(attr.contents): ?  # if isArrayType(attr.contents): ?
        contents=attr.contents
        if isStructType(contents):
          s=prefix+'"%s": { #(0x%lx) -> %s%s},\n'%(field, getaddress(attr), attr.contents.toString(prefix+'\t'),prefix) # use struct printer
        elif isPointerType(contents):
          s=prefix+'"%s": { #(0x%lx) -> %s%s},\n'%(field, getaddress(attr), self._attrToString(attr.contents, None, None, prefix+'\t'), prefix ) # use struct printer
        else:
          s=prefix+'"%s": { #(0x%lx) -> %s\n%s},\n'%(field, getaddress(attr), attr.contents, prefix) # use struct printer
    elif isCStringPointer(attr):
      s=prefix+'"%s": "%s" , #(CString)\n'%(field, attr.string)  
    else:
      s=prefix+'"%s": %s, # DEFAULT toString\n'%(field, repr(attr) )  
    return s

  def __str__(self):
    s=repr(self)+'\n'
    _fieldsTuple = [ (f[0],f[1]) for f in self._fields_] 
    for field,typ in _fieldsTuple:
      attr=getattr(self,field)
      if isStructType(attr):
        s+='%s (@0x%lx) : {\t%s}\n'%(field,ctypes.addressof(attr), attr )  
      elif isBasicTypeArrayType(attr):
        try:
          s+='%s (@0x%lx) : %s\n'%(field,ctypes.addressof(attr), repr(array2bytes(attr)) )  
        except IndexError,e:
          log.error( 'error while reading %s %s'%(repr(attr),type(attr)) )
          
      elif isArrayType(attr): ## array of something else than int
        s+='%s (@0x%lx)  :['%(field, ctypes.addressof(attr),)+','.join(["%s"%(val) for val in attr ])+'],\n'
        continue
      elif isPointerType(attr):
        if not bool(attr) :
          s+='%s (@0x%lx) : 0x%lx\n'%(field,ctypes.addressof(attr), getaddress(attr) )   # only print address/null
        elif not is_address_local(attr) :
          s+='%s (@0x%lx) : 0x%lx (FIELD NOT LOADED)\n'%(field,ctypes.addressof(attr), getaddress(attr) )   # only print address in target space
        else:
          # we can read the pointers contents
          # if isBasicType(attr.contents): ?
          # if isArrayType(attr.contents): ?
          s+='%s (@0x%lx) : (0x%lx) -> {%s}\n'%(field, ctypes.addressof(attr), getaddress(attr), attr.contents) # use struct printer
      elif isCStringPointer(attr):
        s+='%s (@0x%lx) : %s (CString) \n'%(field,ctypes.addressof(attr), attr.string)  
      elif type(attr) is long or type(attr) is int:
        s+='%s : %s\n'%(field, hex(attr) )  
      else:
        #print '*** attr cannot be __str__ ***',field, type(attr)
        s+='%s : %s\n'%(field, repr(attr) )  
    return s
    
  def toPyObject(self):
    ''' returns a Plain Old python object as a perfect copy of this ctypes object.
    '''
    # get self class.
    #log.info("%s %s %s_py"%(self.__class__.__module__, sys.modules[self.__class__.__module__], self.__class__.__name__) )
    my_class=getattr(sys.modules[self.__class__.__module__],"%s_py"%(self.__class__.__name__) )
    my_self=my_class()
    _fieldsTuple = [ (f[0],f[1]) for f in self._fields_] 
    for field,typ in _fieldsTuple:
      attr=getattr(self,field)
      member=self._attrToPyObject(attr,field,typ)
      setattr(my_self, field, member)
    return my_self
    
  def _attrToPyObject(self,attr,field,typ):
    if isStructType(attr):
      obj=attr.toPyObject()
    elif isBasicTypeArrayType(attr): ## array of basic types
      obj=array2bytes(attr)
    elif isArrayType(attr): ## array of something else than int/byte
      obj=[]
      typ=type(attr[0])
      for i in range(0,len(attr)):
        obj.append(self._attrToPyObject( attr[i], i, typ) )
    elif isPointerType(attr):
      if not bool(attr) :
        obj=(None,None)
      elif not is_address_local(attr) :
        obj=(None,getaddress(attr) )
      else:
        contents=attr.contents
        if isStructType(contents) :
          obj=contents.toPyObject()
        elif isPointerType(contents):
          obj=self._attrToPyObject(contents,None,None)
        else: # pointer vers autre chose, le repr() est le seul choix.
          #obj=repr(contents)
          obj=contents
    elif isCStringPointer(attr):
      obj=attr.string
    elif isFunctionType(attr):
      obj = repr(attr)
    else:
      obj = attr
    return obj


class pyObj(object):
  ''' Base class for a plain old python object.
  all haystack/ctypes classes will be translated in this format before pickling.
  
  Operations :
    - toString(self, prefix):  print a nicely formatted data structure
        @param prefix: str to insert before each line (\t after that)
    - findCtypes(self) : checks if a ctypes is to be found somewhere is the object.
                      Useful to check if the object can be pickled.
  '''
  def toString(self, prefix=''):
    s='{\n'
    for attrname,typ in self.__dict__.items():
      attr = getattr(self, attrname)
      s += "%s%s: %s\n"%( prefix, attrname, self._attrToString(attr, attrname, typ, prefix+'\t') )
    s+='}'
    return s

  def _attrToString(self, attr, attrname, typ, prefix ):
    s=''
    if type(attr) is tuple or type(attr) is list:
      for i in xrange(0,len(attr)):
        s += '%s,'%(self._attrToString(attr[i], i ,None, prefix+'\t' ) )
      s = "[%s],"%(s)
    elif not hasattr(attr,'__dict__'):
      s = '%s,'%( repr(attr) )
    elif  isinstance( attr , pyObj):
      s = ' { %s\n},'%( attr.toString(prefix) )
    else:
      s = '%s,'%(repr(attr) )
      print 'ELSE type: %s %s'%(type(attr), type(type(attr)) )
    return s

  def findCtypes(self):
    ret = False
    for attrname,typ in self.__dict__.items():
      attr = getattr(self, attrname)
      if self._attrFindCtypes(attr, attrname,typ ):
        log.warning('Found a ctypes in %s'%(attrname))
        ret = True

  def _attrFindCtypes(self, attr, attrname, typ):
    ret = False
    if type(attr) is tuple or type(attr) is list:
      for el in attr:
        if self._attrFindCtypes(el, 'element', None):
          log.warning('Found a ctypes in array/tuple')
          return True
    elif type(attr).__module__ == 'ctypes':
      log.warning('Found a ctypes in self  %s'%(attr))
      return True
    elif not hasattr(attr,'__dict__'):
      return False
    else:
      #log.warning("else %s"%type(attr))
      ret = False
    return ret

def findCtypesInPyObj(obj):
  ''' check function to help in unpickling errors correction '''
  ret = False
  if isinstance(obj, pyObj):
    if obj.findCtypes():
      log.warning('Found a ctypes in array/tuple')
      return True
  elif type(obj) is tuple or type(obj) is list:
    for el in obj:
      if findCtypesInPyObj(el):
        log.warning('Found a ctypes in array/tuple')
        return True
  return False
      
import inspect,sys

def copyGeneratedClasses(src, dst):
  ''' 
    Copies the members of a generated module into a classic module.
    Name convention : 
    generated: ctypes_libraryname_generated.py
    classic  : ctypes_libraryname.py
    
  @param me : dst module
  @param src : src module, generated
  '''
  __root_module_name,__dot,__module_name = dst.__name__.rpartition('.')
  _loaded=0
  _registered=0
  for (name, klass) in inspect.getmembers(src, inspect.isclass):
    if type(klass) == type(ctypes.Structure):
      if klass.__module__.endswith('%s_generated'%(__module_name) ) :
        setattr(dst, name, klass)
        _loaded+=1
    else:
      #log.debug("%s - %s"%(name, klass))
      pass
  log.debug('loaded %d C structs from %s structs'%( _loaded, src.__name__))
  log.debug('registered %d Pointers types'%( _registered))
  log.debug('There is %d members in %s'%(len(src.__dict__), src.__name__))
  return 


def createPOPOClasses( targetmodule ):
  ''' Load all model classes and create a similar non-ctypes Python class  
    thoses will be used to translate non pickable ctypes into POPOs.
  '''
  _created=0
  for klass,typ in inspect.getmembers(targetmodule, inspect.isclass):
    if typ.__module__.startswith(targetmodule.__name__):
      kpy = type('%s_py'%(klass),( pyObj ,),{})
      # we have to keep a local (model) ref because the class is being created here.
      # and we have a targetmodule ref. because it's asked.
      # and another ref on the real module for the basic type, because, that is probably were it's gonna be used.
      setattr(sys.modules[__name__], '%s_py'%(klass), kpy )
      setattr(targetmodule, '%s_py'%(klass), kpy )
      _created+=1
      if typ.__module__ != targetmodule.__name__: # copy also to generated
        setattr(sys.modules[typ.__module__], '%s_py'%(klass), kpy )
        #log.debug("Created %s_py"%klass)
  log.debug('created %d POPO types'%( _created))
  return

def registerModule( targetmodule ):
  ''' register a ctypes module. To be run by target module.
      all members is module will be registered, against their pointer types,
      in a lookup table
      Creates POPO's to be able to unpickle ctypes.
  '''
  _registered = 0
  for klass,typ in inspect.getmembers(targetmodule, inspect.isclass):
    if typ.__module__.startswith(targetmodule.__name__):
      register( typ )
      _registered += 1
  # create POPO's
  createPOPOClasses( targetmodule )
  log.debug('registered %d types'%( _registered))
  return

# create local POPO ( lodableMembers )
createPOPOClasses(sys.modules[__name__] )
# register LoadableMembers 
register(LoadableMembers)


''' replace c_char_p - it can handle memory parsing without reading it '''
if ctypes.c_char_p.__name__ == 'c_char_p':
  ctypes.c_char_p = CString

''' switch class - we need our methods on ctypes.Structures for generated classes to work  '''
if ctypes.Structure.__name__ == 'Structure':
  ctypes.Structure = LoadableMembers

