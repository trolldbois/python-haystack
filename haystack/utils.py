#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module holds some basic constraint class for the Haystack model.
Several useful function validation are also here, like pointer validation.

'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


import ctypes, os
from struct import pack,unpack
from memory_mapping import readProcessMappings

import logging

log = logging.getLogger('utils')


def is_valid_address(obj, mappings, structType=None):
  ''' 
  @param obj: the obj to evaluate.
  @param mappings: the memory mappings in a list.
  @param structType: the object's type, so the size could be taken in consideration.
  
  Returns False if the object address is NULL.
  Returns False if the object address is not in a mapping.
  Returns False if the object overflows the mapping.
  
  Returns the mapping in which the object stands otherwise.
  '''
  # check for null pointers
  addr = getaddress(obj)
  if addr == 0:
    return False
  return is_valid_address_value(addr, mappings, structType)

def is_valid_address_value(addr, mappings, structType=None):
  ''' 
  @param addr: the address to evaluate.
  @param mappings: the memory mappings in a list.
  @param structType: the object's type, so the size could be taken in consideration.
  
  Returns False if the object address is NULL.
  Returns False if the object address is not in a mapping.
  Returns False if the object overflows the mapping.
  
  Returns the mapping in which the address stands otherwise.
  '''
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
  ''' 
  Costly , checks if obj is mapped to local memory space.

  Returns the memory mapping if found.
    False, otherwise.
  '''
  addr=getaddress(obj)
  if addr == 0:
    return False
  class P:
    pid=os.getpid()
  mappings = readProcessMappings(P()) # memory_mapping
  return is_valid_address(obj,mappings, structType)

def getaddress(obj):
  ''' 
  Returns the address of the struct pointed by the obj, or null if invalid.

  @param obj: a pointer.
  '''
  # check for null pointers
  if bool(obj):
    if not hasattr(obj,'contents'):
      return 0
    return ctypes.addressof(obj.contents)
  else:
    return 0  

def container_of(memberaddr, typ, membername):
  '''
  Returns the instance of typ(), in which the member "membername' is really.
  
  @param memberadd: the address of membername.
  @param typ: the type of the containing structure.
  @param membername: the membername.
  
  Stolen from linux kernel headers.
         const typeof( ((typ *)0)->member ) *__mptr = (ptr);    
        (type *)( (char *)__mptr - offsetof(type,member) );}) 
  '''
  return typ.from_address( memberaddr - offsetof(typ, membername) )

def offsetof(typ, membername):
  '''
  Returns the offset of a member in a structure.
  
  @param typ: the structure type.
  @param membername: the membername in that structure.
  '''
  T=typ()
  return ctypes.addressof(  getattr(T,membername) ) - ctypes.addressof(T)


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
  'c_void_p': 'P',
  'c_void': 'P', ## void in array is void_p ##DEBUG
  }

def array2bytes_(array, typ):
  ''' Convert an array of typ() to a byte string.'''
  arrayLen = len(array)
  if arrayLen == 0:
    return b''
  if typ not in bytestr_fmt:
    log.warning('Unknown ctypes to pack: %s %s'%(typ,array))
    return None
  if typ  == 'c_void':
    return b'' # void array cant be extracted
  fmt=bytestr_fmt[typ]
  sb=b''
  try:
    for el in array:
      sb+=pack(fmt, el)
  except Exception ,e:
    log.warning('%s %s'%(fmt,el))
    #raise e
  return sb

def array2bytes(array):
  ''' Convert an array of undetermined Basic Ctypes class to a byte string, 
  by guessing it's type from it's class name.
  
  This is a bad example of introspection.
  '''
  if not isBasicTypeArrayType(array):
    return b'NOT-AN-BasicType-ARRAY'
  # BEURK
  #log.info(type(array).__name__.split('_'))
  typ='_'.join(type(array).__name__.split('_')[:2])
  return array2bytes_(array,typ)

def bytes2array(bytes, typ):
  ''' Converts a bytestring in a ctypes array of typ() elements.'''
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
  import struct
  try:
    for i in range(0,arrayLen):
      array[i]=unpack(fmt, bytes[typLen*i:typLen*(i+1)])[0]
  except struct.error,e:
    log.error('format:%s typLen*i:typLen*(i+1) = %d:%d'%(fmt, typLen*i,typLen*(i+1)))
    raise e
  return array


def pointer2bytes(attr,nbElement):
  ''' 
  Returns an array from a ctypes POINTER, geiven the number of elements.
  
  @param attr: the structure member.
  @param nbElement: the number of element in the array.
  '''
  # attr is a pointer and we want to read elementSize of type(attr.contents))
  if not is_address_local(attr):
    return 'POINTER NOT LOCAL'
  firstElementAddr=getaddress(attr)
  array=(type(attr.contents)*nbElement).from_address(firstElementAddr)
  # we have an array type starting at attr.contents[0]
  return array2bytes(array)

def isCTypes(obj):
  ''' Checks if an object is a ctypes type object'''
  return  (type(obj).__module__ in ['ctypes','_ctypes']) 
    
def isBasicType(obj):
  ''' Checks if an object is a ctypes basic type, or a python basic type.'''
  return not isPointerType(obj) and not isFunctionType(obj) and (type(obj).__module__ in ['ctypes','_ctypes','__builtin__']) 

def isStructType(obj):
  ''' Checks if an object is a ctypes Structure.'''
  return isinstance(obj, ctypes.Structure)

__ptrt = type(ctypes.POINTER(ctypes.c_int))
def isPointerType(obj):
  ''' Checks if an object is a ctypes pointer.'''
  return __ptrt == type(type(obj)) or isFunctionType(obj)

def isBasicTypeArrayType(obj):
  ''' Checks if an object is a array of basic types.
  It checks the type of the first element.
  The array should not be null :).
  '''
  if isArrayType(obj):
    if len(obj) == 0:
      return False # no len is no BasicType
    if isPointerType(obj[0]):
      return False
    if isBasicType(obj[0]):
      return True
  return False

__arrayt = type(ctypes.c_int*1)
def isArrayType(obj):
  ''' Checks if an object is a ctype array.'''
  return __arrayt == type(type(obj))

__cfuncptrt = type(type(ctypes.memmove))
def isFunctionType(obj):
  ''' Checks if an object is a function pointer.'''
  return __cfuncptrt == type(type(obj))

def isCStringPointer(obj):
  ''' Checks if an object is our CString.'''
  return obj.__class__.__name__ == 'CString'

def isUnionType(obj):
  ''' Checks if an object is a Union type.'''
  return isinstance(obj,ctypes.Union) and not isCStringPointer(obj)


class IgnoreMember:
  ''' 
  Constraint class for the Haystack model.
  If this constraints is applied on a Structure member, 
  the member will be ignored by the validation engine.
  '''
  def __contains__(self,obj):
    return True

class RangeValue:
  ''' 
  Constraint class for the Haystack model.
  If this constraints is applied on a Structure member, 
  the member has to be between 'low' and 'high' values to be
  considered as Valid.
  '''
  def __init__(self,low,high):
    self.low=low
    self.high=high
  def __contains__(self,obj):
    return self.low <= obj <= self.high
  def __eq__(self,obj):
    return self.low <= obj <= self.high

class NotNullComparable:
  ''' 
  Constraint class for the Haystack model.
  If this constraints is applied on a Structure member, 
  the member should not be null to be considered valid by the validation engine.
  '''
  def __contains__(self,obj):
    return bool(obj)
  def __eq__(self,obj):
    return bool(obj)

''' 
Constraint class for the Haystack model.
If this constraints is applied on a Structure member, 
the member should not be null to be considered valid by the validation engine.
'''
NotNull=NotNullComparable()



py_xrange=xrange
def xrange(start, end, step):
  ''' stoupid xrange can't handle long ints... '''
  end=end-start
  for val in py_xrange(0, end, step):
    yield start+val
  return

