#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import collections
import struct
import itertools

from haystack.config import Config
import re_string

log = logging.getLogger('field')

## Field related functions and classes

def makeArrayField(parent, fields): 
  #vaddr = parent.vaddr+firstField.offset
  newField = ArrayField(parent, fields)
  return newField


class FieldType:
  types = set()
  def __init__(self, _id, basename, ctypes, sig, isPtr=False):
    self._id = _id
    self.basename = basename
    self.ctypes = ctypes
    self.sig = sig
    self.isPtr = isPtr
  @classmethod
  def makePOINTER(cls, typ):
    if typ == FieldType.STRING:
      return FieldType.STRING_POINTER
    return cls( typ._id+0xa, typ.basename+'_ptr', 'ctypes.POINTER(%s)'%(typ.ctypes), 'P', True)

  @classmethod
  def makeStructField(cls, parent, offset, fields): # struct name should be the vaddr... otherwise itgonna be confusing
    import structure
    vaddr = parent.vaddr+offset
    newfieldType = FieldTypeStruct('%lx'%(vaddr), fields)
    newfieldType.setStruct(structure.AnonymousStructInstance(parent.mappings, vaddr, parent.bytes[offset:offset+len(newfieldType)] ) )
    newField = Field(parent, offset, newfieldType, len(newfieldType), False)
    return newField

  def __cmp__(self, other):
    if not isinstance(other, FieldType):
      raise TypeError('%s %s'%(self.__class__, other.__class__))
    return cmp(self._id, other._id)

  def __hash__(self):
    return hash(self._id)

  def __str__(self):
    return '<FieldType %s>'%(self.basename)

  def __repr__(self):
    return '<t:%s>'%(self.basename)

class FieldTypeStruct(FieldType):
  def __init__(self, name, fields):
    FieldType.__init__(self, 0x3, 'struct', name, 'K', isPtr=False)
    self.size = sum([len(f) for f in fields])

  def setStruct(self, struct):
    self._struct = struct
    
  def getStruct(self):
    return self._struct

  def __len__(self):
    return self.size
  
class FieldTypeArray(FieldType):
  def __init__(self, basicTypeName):
    FieldType.__init__(self, 0x8, 'array_%s'%basicTypeName, None, 'a', isPtr=False)


FieldType.UNKNOWN  = FieldType(0x0,  'untyped',   'ctypes.c_ubyte',   'u')
FieldType.POINTER  = FieldType(0xa,  'ptr',       'ctypes.c_void_p',  'P', True)
FieldType.ZEROES   = FieldType(0x2,  'zerroes',   'ctypes.c_ubyte',   'z')
FieldType.STRUCT   = FieldType(0x3, 'struct',      'Structure',    'K')
FieldType.STRING   = FieldType(0x4, 'text',      'ctypes.c_char',    'T')
FieldType.STRING_POINTER   = FieldType(0xb, 'text_ptr',      'ctypes.c_char_p', 's', True)
FieldType.INTEGER  = FieldType(0x5, 'int',       'ctypes.c_uint',    'I')
FieldType.SMALLINT = FieldType(0x6, 'small_int', 'ctypes.c_uint',    'i')
FieldType.SIGNED_SMALLINT = FieldType(0x7, 'signed_small_int', 'ctypes.c_int',    'i')
FieldType.ARRAY    = FieldType(0x8, 'array',     'Array',   'a')
FieldType.BYTEARRAY    = FieldType(0x9, 'array',     'ctypes.c_ubyte',   'a')
#FieldType.ARRAY_CHAR_P = FieldType(0x9, 'array_char_p',     'ctypes.c_char_p',   'Sp')
FieldType.PADDING  = FieldType(0xf, 'pad',       'ctypes.c_ubyte',   'X')

  
class Field:
  def __init__(self, astruct, offset, typename, size, isPadding):
    self.struct = astruct
    self.offset = offset
    self.size = size
    self.typename = typename
    self.padding = isPadding
    self.typesTested = []
    self.value = None
    self.comment = ''
    self.usercomment = ''  
    self.decoded = False
    if typename != FieldType.UNKNOWN:
      self.decoded = True
      self._check()
    
  def setComment(self, txt):
    self.usercomment = '# %s'%txt
  def getComment(self):
    return self.usercomment
    
  def isString(self): # null terminated
    return self.typename == FieldType.STRING
  def isPointer(self): # 
    return self.typename.isPtr
  def isZeroes(self): # 
    return self.typename == FieldType.ZEROES
  def isArray(self): # will be overloaded
    return self.typename == FieldType.ARRAY or self.typename == FieldType.BYTEARRAY 
  def isInteger(self): # 
    return self.typename == FieldType.INTEGER or self.typename == FieldType.SMALLINT or self.typename == FieldType.SIGNED_SMALLINT

  def checkString(self):
    ''' if there is no \x00 termination, its not a string
    that means that if we have a bad pointer in the middle of a string, 
    the first part will not be understood as a string'''
    bytes = self.struct.bytes[self.offset:]
    ret = re_string.startsWithNulTerminatedString(bytes)
    if not ret:
      self.typesTested.append(FieldType.STRING)
      #log.warning('STRING: This is not a string %s'%(self))
      return False
    else:
      self.size, self.encoding, self.value = ret 
      self.value += '\x00' # null terminated
      self.size += 1 # null terminated
      log.debug('STRING: Found a string "%s"/%d for encoding %s, field %s'%( repr(self.value), self.size, self.encoding, self))
      return True

  def checkPointer(self):
    if (self.offset%Config.WORDSIZE != 0):
      return False
    bytes = self.struct.bytes[self.offset:self.offset+Config.WORDSIZE]
    if len(bytes) != Config.WORDSIZE:
      return False      
    value = bytes.unpack('L',bytes)[0] #TODO biteorder
    log.debug('checkPointer offset:%s value:%s'%(self.offset, hex(value)))
    # TODO check if pointer value is in range of mappings and set self.comment to pathname value of pointer
    if value in self.struct.mappings:
      self.value = value
      self.size = Config.WORDSIZE
      self.comment = self.struct.mappings.getMmapForAddr(self.value).pathname
      self.typename = FieldType.POINTER
      return True
    else:
      return False

  def checkZeroes(self):
    if self.checkLeadingZeroes():
      log.debug ('ZERO: decoded a zeroes START padding from offset %d:%d'%(self.offset,self.offset+self.size))
    elif self.checkEndingZeroes():
      log.debug ('ZERO: decoded a zeroes ENDING padding from offset %d:%d'%(self.offset,self.offset+self.size))
    elif self.checkContainsZeroes():
      log.debug ('ZERO: decoded a zeroes CONTAINS padding from offset %d:%d'%(self.offset,self.offset+self.size))
    else :
      return False
    self.typename = FieldType.ZEROES
    #Not so good
    #if (self.size % Config.WORDSIZE) == 0 and (self.size//Config.WORDSIZE) < 8: # 8 zerroes is more a buffer than ints
    if (self.size == Config.WORDSIZE):
      self.typename = FieldType.SMALLINT
      self.value = 0
      self.checkInteger()
    return True  
  
  def checkLeadingZeroes(self):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    previous = -1
    for i, val in enumerate(bytes):
      log.debug('LEAD: charAt:%s,value:%s  bytes[%d:%d]: %s' %(i, ord(val), self.offset+i,self.offset+self.size, repr(bytes[i:i+32]) ))
      if (self.offset+i) % Config.WORDSIZE == 0: # aligned word
        previous = i
      if val != '\x00':  # ah ! its not null !
        if previous == i: # aligned word
          if i > 0: # we have at least a byte of padding
            self.size = i
            self.value = bytes[:self.size]
            return True
          else: # first byte is not null
            return False
        else: # unaligned word, we can say the padding stopped at the previous alignement
          if previous <= 0: # never was a padding
            return False
          else: # the padding stopped after 'previous' bytes 
            self.size = previous
            self.value = bytes[:self.size]
            return True
      #continue
    if previous != -1:
      # self.size = i # change is not necessary
      self.value = bytes
      return True
    return False

  def checkEndingZeroes(self):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    start = len(bytes)-len(bytes)%Config.WORDSIZE
    if start < 4:
      log.debug('ENDING: bytes are %d long'%(start))
      return False
    log.debug('ENDING: range(len(bytes)-Config.WORDSIZE,-1,-Config.WORDSIZE): %s'%(len(bytes)-Config.WORDSIZE))
    for i in range(len(bytes)-Config.WORDSIZE,-1,-Config.WORDSIZE): #len(bytes)-Config.WORDSIZE
      if bytes.unpack('L',bytes[i:i+Config.WORDSIZE])[0] == 0: 
        start = i
      else:
        break
    if start < len(bytes):
      self.offset = self.offset+start
      self.value = bytes[start:]
      self.size = len(self.value)
      log.debug('ENDING: Ending zerroes from offset %d:%d'%(self.offset,self.offset+self.size))
      return True
    return False    

  def checkContainsZeroes(self):
    bytes = self.struct.bytes[self.offset:self.offset+self.size]    
    size = len(bytes)
    if size <= 11:
      return False
    log.debug('MIDZEROES: range(len(bytes)-Config.WORDSIZE,-1,-Config.WORDSIZE): %s'%(len(bytes)-Config.WORDSIZE))
    maxOffset = size - Config.WORDSIZE
    # align offset
    it = itertools.dropwhile( lambda x: (x%Config.WORDSIZE != 0) , xrange(0, maxOffset) )
    aligned = it.next() # not exceptionnable here
    log.debug('aligned:%s'%aligned)
    it = itertools.dropwhile( lambda x: (bytes.unpack('L',bytes[x:x+Config.WORDSIZE])[0] != 0)  , xrange(aligned, maxOffset, Config.WORDSIZE) )
    try: 
      start = it.next()
    except StopIteration,e:
      log.debug('Did not find zeroes aligned')
      return False
    it = itertools.takewhile( lambda x: (bytes.unpack('L',bytes[x:x+Config.WORDSIZE])[0] == 0)  , xrange(start, maxOffset, Config.WORDSIZE) )
    end = max(it) + Config.WORDSIZE
    size = end-start 
    if size < 4:
      return False
    log.debug('CONTAINS: contains %s zeroes at start %d'%(size, start))
    self.size = size
    self.value = bytes[start:end]    
    self.offset = self.offset+start
    log.debug('CONTAINS: zerroes from offset %d:%d'%(self.offset,self.offset+self.size))
    return True

  def checkIntegerArray(self):
    # this should be last resort
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < 4:
      return False
    ctr = collections.Counter([ bytes[i:i+Config.WORDSIZE] for i in range(len(bytes)) ] )
    floor = max(1,int(size*.1)) # 10 % variation in values
    #commons = [ c for c,nb in ctr.most_common() if nb > 2 ]
    commons = ctr.most_common()
    if len(commons) > floor:
      return False # too many different values
    # few values. it migth be an array
    self.size = size
    self.values = bytes
    self.comment = '10%% var in values: %s'%(','.join([ repr(v) for v,nb in commons]))
    return True
        
  def checkArrayCharP(self):
    pass
    
  def checkInteger(self):
    log.debug('checking Integer')
    if self.checkSmallInt():
      return True
    elif self.checkSmallInt(endianess='>'):
      return True
    elif self.size == Config.WORDSIZE:
      bytes = self.struct.bytes[self.offset:self.offset+self.size]
      self.value = bytes.unpack('@L',bytes[:Config.WORDSIZE])[0] 
      self.typename = FieldType.INTEGER
      self.endianess = '@' # unknown
      return True
    return False

  def checkSmallInt(self, endianess='<'):
    # TODO
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < Config.WORDSIZE:
      return False
    val = bytes.unpack('%sL'%endianess,bytes[:Config.WORDSIZE])[0] 
    if val < 0xffff:
      self.value = val
      self.size = Config.WORDSIZE
      self.typename = FieldType.SMALLINT
      self.endianess = endianess
      return True
    else: # check signed int
      val = bytes.unpack('%sL'%endianess,bytes[:Config.WORDSIZE])[0] 
      if -0xffff <= val <= 0xffff:
        self.value = val
        self.size = Config.WORDSIZE
        self.typename = FieldType.SIGNED_SMALLINT
        self.endianess = endianess
        return True
      return False
    return False

    
  def _check(self):
    if self.typename == FieldType.UNKNOWN:
      raise TypeError('Please call decodeType on unknown tyep fields')
    # try all possible things
    ret = True
    if self.isString():
      ret = self.checkString()
    elif self.isPointer():
      ret = self.checkPointer()
    elif self.isInteger():
      ret = self.checkInteger()
    return ret
        
  def decodeType(self):
    if self.decoded:
      return self.typename
    if self.typename != FieldType.UNKNOWN:
      raise TypeError('I wont coherce this Field if you think its another type')
    # try all possible things
    if self.checkString(): # Found a new string...
      self.typename = FieldType.STRING
    elif self.checkZeroes():
      # ok, inlined
      pass
    elif self.checkPointer():
      log.debug ('POINTER: decoded a pointer to %s from offset %d:%d'%(self.comment, self.offset,self.offset+self.size))
    elif self.checkInteger():
      log.debug ('INTEGER: decoded an int from offset %d:%d'%(self.offset,self.offset+self.size))
    #elif self.checkIntegerArray():
    #  self.typename = FieldType.ARRAY
    else:
      # check other types
      self.decoded = False
      return None
    # typename is good
    self.decoded = True
    self.padding = False
    self.setName('%s_%d'%(self.typename.basename, self.offset))
    return self.typename
  
  def setCTypes(self, name):
    self.ctypes = name
  
  def getCTypes(self):
    if hasattr(self, 'ctypes'):
      return self.ctypes
    if self.isString() or self.isZeroes():
      return '%s * %d' %(self.typename.ctypes, len(self) )
    if self.isArray():
      return '%s * %d' %(self.typename.ctypes, len(self)/self.element_size ) #TODO should be in type
    if self.typename == FieldType.UNKNOWN:
      return '%s * %d' %(self.typename.ctypes, len(self) )
    return self.typename.ctypes
  
  def setName(self, name):
    self.name = name
  
  def getName(self):
    if hasattr(self, 'name'):
      return self.name
    else:
      return '%s_%s'%(self.typename.basename, self.offset)
    
  def __hash__(self):
    return hash(self.offset, self.size, self.typename)
      
  #def tuple(self):
  #  return (self.offset, self.size, self.typename)

  def __cmp__(self, other):
    # XXX : Perf... cmp with other type should raise a type error the dev head...
    #if not isinstance(other, Field):
    #  raise TypeError
    return cmp((self.offset, self.size, self.typename), (other.offset, other.size, other.typename))

  def __len__(self):
    return int(self.size) ## some long come and goes

  def __str__(self):
    i = 'new'
    if self in self.struct.fields:
      i = self.struct.fields.index(self)
    return '<Field %s offset:%d size:%s t:%s'%(i, self.offset, self.size, self.typename)
    
  def getValue(self, maxLen):
    bytes = self._getValue(maxLen)
    bl = len(str(bytes))
    if bl >= maxLen:
      bytes = str(bytes[:maxLen/2])+'...'+str(bytes[-(maxLen/2):]) # idlike to see the end
    return bytes
        
  def _getValue(self, maxLen):
    if len(self) == 0:
      return '<-haystack no pattern found->'
    if self.isString():
      bytes = repr(self.value)
    elif self.isInteger():
      return self.value #bytes.unpack('L',(self.struct.bytes[self.offset:self.offset+len(self)]) )[0]
    elif self.isZeroes():
      bytes=repr(self.value)#'\\x00'*len(self)
    elif self.isArray():
      log.warning('ARRAY in Field type, %s'%self.typename)
      bytes= ''.join(['[',','.join([el.toString() for el in self.elements]),']'])
    elif self.padding or self.typename == FieldType.UNKNOWN:
      bytes = self.struct.bytes[self.offset:self.offset+len(self)]
    else: # bytearray, pointer...
      return self.value
    return bytes
  
  def getSignature(self):
    return (self.typename, self.size)
  
  def toString(self, prefix):
    #log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
    #    %(self.isPointer(), self.isInteger(), self.isZeroes(), self.padding, self.typename.basename) )
  
    if self.isPointer():
      comment = '# @ %lx %s %s'%( self.value, self.comment, self.usercomment ) 
    elif self.isInteger():
      comment = '#  %s %s %s'%( self.getValue(Config.commentMaxSize), self.comment, self.usercomment ) 
    elif self.isZeroes():
      comment = '# %s %s zeroes:%s'%( self.comment, self.usercomment, self.getValue(Config.commentMaxSize)  ) 
    elif self.isString():
      comment = '#  %s %s %s'%( self.comment, self.usercomment, self.getValue(Config.commentMaxSize) ) 
    else:
      #unknown
      comment = '# %s %s else bytes:%s'%( self.comment, self.usercomment, repr(self.getValue(Config.commentMaxSize)) ) 
          
    fstr = "%s( '%s' , %s ), %s\n" % (prefix, self.getName(), self.getCTypes(), comment) 
    return fstr
    

class ArrayField(Field):
  def __init__(self, astruct, elements): #, basicTypename, basicTypeSize ): # use first element to get that info
    self.struct = astruct
    self.offset = elements[0].offset
    self.typename = FieldTypeArray(elements[0].typename.basename)

    self.elements = elements
    self.nbElements = len(elements)
    self.basicTypeSize = len(elements[0])
    self.basicTypename = elements[0].typename

    self.size = self.basicTypeSize * len(self.elements)
    self.padding = False
    self.value = None
    self.comment = ''
    self.usercomment = ''  
    self.decoded = True
  
  def isArray(self):
    return True

  def getCTypes(self):
    if hasattr(self, 'ctypes'):
      return self.ctypes
    return '%s * %d' %(self.basicTypename.ctypes, self.nbElements )

  def _getValue(self, maxLen):
    bytes= ''.join(['[',','.join([str(el._getValue(10)) for el in self.elements]),']'])
    return bytes

  def toString(self, prefix):
    log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
        %(self.isPointer(), self.isInteger(), self.isZeroes(), self.padding, self.typename.basename) )
    #
    comment = '# %s %s array:%s'%( self.comment, self.usercomment, self.getValue(Config.commentMaxSize) )
    fstr = "%s( '%s' , %s ), %s\n" % (prefix, self.getName(), self.getCTypes(), comment) 
    return fstr


def isIntegerType(typ):
  return typ == FieldType.INTEGER or typ == FieldType.SMALLINT or typ == FieldType.SIGNED_SMALLINT 

