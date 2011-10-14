#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, os, pickle, time, sys
import collections
import re
import struct
import ctypes
import array
import itertools
import numbers
import string

from utils import xrange
from cache_utils import int_array_cache,int_array_save
import memory_dumper
import signature 
from pattern import Config
import re_string

log = logging.getLogger('progressive')

# a 12 Mo heap takes 30 minutes on my slow notebook
# what is \xb2 padding for ?
# huge bug with zerroes fields aggregation
# the empty space at the end of the heap is making the reverse quite slow.... logs outputs line rate 10/sec againt 2k/sec

# TODO look for VFT and malloc metadata ?
# se stdc++ to unmangle c++
# vivisect ?
# TODO 1: make an interactive thread on that anon_struct and a struct Comparator to find similar struct.
#         that is a first step towards structure identification && naming. + caching of info
#      2: dump ctypes structure into python file + cache (vaddr, Structurectypes ) to pickle file ( reloading/continue possible with less recalculation )
# create a typename for \xff * 8/16. buffer color ? array of char?

# Compare sruct type from parent with multiple pointer (


def make(opts):
  log.info('[+] Extracting structures from pointer values and offsets.')
  ## get the list of pointers values pointing to heap
  ## need cache
  mappings = memory_dumper.load( opts.dumpfile, lazy=True)  
  values,heap_addrs, aligned, not_aligned = getHeapPointers(opts.dumpfile.name, mappings)
  # we
  if not os.access(Config.structsCacheDir, os.F_OK):
    os.mkdir(Config.structsCacheDir )
  heap = mappings.getHeap()
  log.info('[+] Reversing %s'%(heap))
  # creates
  #structCache = {}
  for anon_struct in buildAnonymousStructs(mappings, heap, aligned, not_aligned, heap_addrs, reverse=False): # reverse is way too slow...
    #anon_struct.save()
    # TODO regexp search on structs/bytearray.
    # regexp could be better if crossed against another dump.
    #
    log.info(anon_struct.toString())
    #structCache[ anon_struct.vaddr ] = anon_struct
    pass

  
  ## we have :
  ##  resolved PinnedPointers on all sigs in ppMapper.resolved
  ##  unresolved PP in ppMapper.unresolved
  
  ## next step
  log.info('Pin resolved PinnedPointers to their respective heap.')


def getHeapPointers(dumpfilename, mappings):
  ''' Search Heap pointers values in stack and heap.
      records values and pointers address in heap.
  '''
  F_VALUES = dumpfilename+'.heap+stack.pointers.values'
  F_ADDRS = dumpfilename+'.heap.pointers.addrs'
  
  values = int_array_cache(F_VALUES)
  heap_addrs = int_array_cache(F_ADDRS)
  if values is None or heap_addrs is None:
    log.info('Making new cache')
    log.info('getting pointers values from stack ')
    stack_enumerator = signature.PointerEnumerator(mappings.getStack())
    stack_enumerator.setTargetMapping(mappings.getHeap()) #only interested in heap pointers
    stack_enum = stack_enumerator.search()
    stack_addrs, stack_values = zip(*stack_enum)
    log.info('  got %d pointers '%(len(stack_enum)) )
    log.info('Merging pointers from heap')
    heap_enum = signature.PointerEnumerator(mappings.getHeap()).search()
    heap_addrs, heap_values = zip(*heap_enum)
    log.info('  got %d pointers '%(len(heap_enum)) )
    # merge
    values = sorted(set(heap_values+stack_values))
    int_array_save(F_VALUES , values)
    int_array_save(F_ADDRS, heap_addrs)
    log.info('we have %d unique pointers values out of %d orig.'%(len(values), len(heap_values)+len(stack_values)) )
  else:
    log.info('[+] Loading from cache')
    log.info('    [-] we have %d unique pointers values, and %d pointers in heap .'%(len(values), len(heap_addrs)) )
  aligned = filter(lambda x: (x%4) == 0, values)
  not_aligned = sorted( set(values)^set(aligned))
  log.info('         only %d are aligned values.'%(len(aligned) ) )
  return values,heap_addrs, aligned, not_aligned

def buildAnonymousStructs(mappings, heap, _aligned, not_aligned, p_addrs, reverse=False):
  ''' values: ALIGNED pointer values
  '''
  structCache = {}
  lengths=[]
  
  aligned = list(_aligned)
  for i in range(len(aligned)-1):
    lengths.append(aligned[i+1]-aligned[i])
  lengths.append(heap.end-aligned[-1]) # add tail
  
  addrs = list(p_addrs)
  unaligned = list(not_aligned)
  
  if reverse:
    aligned.reverse()
    lengths.reverse()
    addrs.reverse()
    unaligned.reverse()
    dequeue=dequeue_reverse
    
  nbMembers = 0
  # make AnonymousStruct
  for i in range(len(aligned)):
    hasMembers=False
    start = aligned[i]
    size = lengths[i]
    # the pointers field address/offset
    addrs, my_pointers_addrs = dequeue(addrs, start, start+size)  ### this is not reverse-compatible
    # the pointers values, that are not aligned
    unaligned, my_unaligned_addrs = dequeue(unaligned, start, start+size)
    ### read the struct
    anon = AnonymousStructInstance(mappings, aligned[i], heap.readBytes(start, size) )
    ##log.debug('Created a struct with %d pointers fields'%( len(my_pointers_addrs) ))
    # get pointers addrs in start -> start+size
    for p_addr in my_pointers_addrs:
      f = anon.addField(p_addr, FieldType.POINTER, Config.WORDSIZE, False)
    ## set field for unaligned pointers, that sometimes gives good results ( char[][] )
    for p_addr in my_unaligned_addrs:
      if anon.guessField(p_addr) is not None: #, FieldType.UKNOWN):
        nbMembers+=1
        hasMembers=True
      # not added
    # try to decode fields
    log.debug('build: decoding fields')
    anon.decodeFields()
    # try to resolve pointers
    log.debug('build: resolve pointers')
    anon.resolvePointers(structCache)
    # debug
    if hasMembers:
      for _f in anon.fields:
        if _f.size == -1:
          log.debug('ERROR, %s '%(_f))
      log.debug('Created a struct %s with %d fields'%( anon, len(anon.fields) ))
      #log.debug(anon.toString())
    #
    structCache[ anon.vaddr ] = anon
    yield anon
  log.info('Typed %d stringfields'%(nbMembers))
  return

def filterPointersBetween(addrs, start, end):
  ''' start <=  x <  end-4'''
  return itertools.takewhile( lambda x: x>end-Config.WORDSIZE, itertools.dropwhile( lambda x: x<start, addrs) )

def dequeue(addrs, start, end):
  ''' start <=  x <  end-4'''
  ret = []
  while len(addrs)> 0  and addrs[0] < start:
    addrs.pop(0)
  while len(addrs)> 0  and addrs[0] >= start and addrs[0] <= end - Config.WORDSIZE:
    ret.append(addrs.pop(0))
  return addrs, ret
  

class AnonymousStructInstance:
  '''
  AnonymousStruct in absolute address space.
  Comparaison between struct is done is relative addresse space.
  '''
  def __init__(self, mappings, vaddr, bytes, prefix=None):
    self.mappings = mappings
    self.vaddr = vaddr
    self.bytes = bytes
    self.fields = []
    self.pointersType = {}
    if prefix is None:
      self.prefixname = '%lx'%(self.vaddr)
    else:
      self.prefixname = '%lx_%s'%( self.vaddr, self.prefix)
    self.resolved = False
    self.pointerResolved = False
    return
  
  def guessField(self, vaddr, typename=None, size=-1, padding=False ):
    offset = vaddr - self.vaddr
    if offset < 0 or offset > len(self):
      raise IndexError()
    if typename is None:
      typename = FieldType.UNKNOWN
    ## find the maximum size
    if size == -1:
      try: 
        nextStruct = itertools.dropwhile(lambda x: (x.offset < offset), sorted(self.fields) ).next()
        nextStructOffset = nextStruct.offset
      except StopIteration, e:
        nextStructOffset = len(self)
      maxFieldSize = nextStructOffset - offset
      size = maxFieldSize
    ##
    field = Field(self, offset, typename, size, padding)
    if field.isPointer():
      self._setFieldAsPointerField(field)
    if typename == FieldType.UNKNOWN:
      if not field.decodeType():
        return None
    elif not field.check():
      return None
    if field.size == -1:
      raise ValueError('error here %s %s'%(field, field.typename))
    # field has been typed
    self.fields.append(field)
    self.fields.sort()
    return field

  def addField(self, vaddr, typename, size, padding ):
    offset = vaddr - self.vaddr
    return self._addField(offset, typename, size, padding)
    
  def _addField(self, offset, typename, size, padding):
    if offset < 0 or offset > len(self):
      raise IndexError()
    if typename is None:
      raise ValueError()
    # make a field with no autodecode
    field = Field(self, offset, typename, size, padding)
    # field has been typed
    self.fields.append(field)
    self.fields.sort()
    return field

  def save(self):
    self.fname = os.path.sep.join([Config.structsCacheDir, str(self)])
    pickle.dump(self, file(self.fname,'w'))
    return
  
  def _check(self,field):
    # TODO check against other fields
    return field.check()

  def decodeFields(self):
    ''' list all gaps between known fields 
        try to decode their type
            if no  pass, do not populate
            if yes add a new field
        compare the size of the gap and the size of the fiel
    '''
    # should be done by 
    #if len(self.fields) == 0: ## add a fake all-struct field
    #  self._addField(0, FieldType.UNKNOWN, size, True)
    self._fixGaps() # add padding zones
    gaps = [ f for f in self.fields if f.padding == True ] 
    while len(gaps) > 0 :
      # try to decode padding zone
      for field in self.fields:
        if field.decoded: # do not redecode, save
          continue
        #
        fieldType = field.decodeType()
        if fieldType is None: # we could not decode. mark it as unknown
          field.padding = False
          continue
        # Found a new field in a padding, with a probable type...
        pass
      # reroll until completion
      self._fixGaps() 
      gaps = [ f for f in self.fields if f.padding == True ] 
    #endwhile
  return

  def _fixGaps(self):
    ''' Fix this structure and populate empty offsets with default unknown padding fields '''
    nextoffset = 0
    self._gaps = 0
    overlaps = False
    self.fields = [ f for f in self.fields if f.padding != True ] # clean paddings to check new fields
    myfields = sorted(self.fields)
    for f in myfields:
      if f.offset > nextoffset : # add temp padding field
        log.debug('fixGaps: adding field at offset %d'%(f.offset))
        self._gaps += 1
        padding = self._addField( nextoffset, FieldType.UNKOWN, f.offset-nextoffset, True)
      elif f.offset < nextoffset :
        log.warning('fixGaps: overlapping fields at offset %d'%(f.offset))
        overlaps = True
      else: # == 
        pass
      nextoffset = f.offset + len(f)
    # conclude on QUEUE insertion
    if nextoffset < len(self):
      self._gaps += 1
      padding = self._addField( nextoffset, FieldType.UNKOWN, len(self)-nextoffset, True)
    if self._gaps == 0:
      self.resolved = True
    if overlaps:
      self._fixOverlaps()
    self.fields.sort()
    return
  

  def _fixOverlaps(self):
    ''' fix overlapping string fields '''
    fields = sorted([ f for f in self.fields if f.padding != True ]) # clean paddings to check new fields
    for f1, f2 in self._getOverlapping():
      log.debug('overlappings %s %s'%(f1,f2))
      f1_end = f1.offset+len(f1)
      f2_end = f2.offset+len(f2)
      if (f1.typename == f2.typename and
          f2_end == f1_end ): # same end, same type
        self.fields.remove(f2) # use the last one
        log.debug('Cleaned a  field overlaps %s %s'%(f1, f2))
      elif f1.isZeroes() and f2.isZeroes(): # aggregate
        log.debug('aggregate Zeroes')
        start = min(f1.offset,f2.offset)
        size = max(f1_end, f2_end)-start
        try:
          self.fields.remove(f1)
          self.fields.remove(f2)
          self.fields.append( Field(self, start, FieldType.ZEROES, size, False) )
        except ValueError,e:
          log.error('please bugfix')
    return
  
  def _getOverlapping(self):
    fields = sorted([ f for f in self.fields if f.padding != True ]) # clean paddings to check new fields
    lastend = 0
    oldf = None
    for f in fields:
      newend = f.offset + len(f)
      if f.offset < lastend:  ## overlaps
        yield ( oldf, f )
      oldf = f
      lastend = newend
    return
  
      
  def __getitem__(self, i):
    return self.fields[i]
    
  def __len__(self):
    return len(self.bytes)


  def resolvePointers(self, structCache):
    resolved = 0
    for field,pointed in self.getPointerFields().items():
      # if pointed is not None:  # erase previous info
      tgt = None
      if field.value in structCache:
        tgt = structCache[field.value]
        resolved+=1
      self._setFieldAsPointerField(field, tgt)
    #
    if len(self.pointersType) == resolved:
      if resolved != 0 :
        log.debug('%s pointers are fully resolved'%(self))
      self.pointerResolved = True
    else:
      self.pointerResolved = False
    return
    
  def getPointerFields(self):
    return self.pointersType
  
  def _setFieldAsPointerField(self, field, target=None):
    self.pointersType[field] = target
    if target is not None:
      field.setName('%s_%s'%(field.typename.basename, target))
  
  def getSignature(self):
    return ''.join([f.getSignature() for f in self.fields])
  
  def toString(self):
    self._fixGaps()
    fieldsString = '[ \n%s ]'% ( ''.join([ field.toString('\t') for field in self.fields]))
    info = 'resolved:%s'%(self.resolved)
    if len(self.getPointerFields()) != 0:
      info += ' pointerResolved:%s'%(self.pointerResolved)
    ctypes_def = '''
class %s(LoadableMembers):  # %s
  _fields_ = %s

''' % (self, info, fieldsString)
    return ctypes_def

  def __str__(self):
    return 'AnonymousStruct_%s_%s_%s'%(len(self), self.prefixname, len(self.fields) )
  


class FieldType:
  def __init__(self, sig, basename, ctypes):
    self.sig = sig
    self.basename = basename
    self.ctypes = ctypes

FieldType.UNKNOWN  = FieldType(0x0,  'untyped',   'unknown')
FieldType.POINTER  = FieldType(0x1,  'ptr',       'ctypes.c_void_p')
FieldType.ZEROES   = FieldType(0x2,  'zerroes',   'ctypes.c_ubyte')
FieldType.STRING   = FieldType(0x10, 'text',      'ctypes.c_char')
FieldType.INTEGER  = FieldType(0x40, 'int',       'ctypes.c_uint')
FieldType.SMALLINT = FieldType(0x41, 'small_int', 'ctypes.c_uint')
FieldType.ARRAY    = FieldType(0x50, 'array',     'ctypes.c_ubyte')
FieldType.PADDING  = FieldType(0x90, 'pad',       'ctypes.c_ubyte')

  
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
    
  def setComment(self, txt):
    self.usercomment = '# %s'%txt
  def getComment(self):
    return self.usercomment
    
  def isString(self): # null terminated
    return self.typename == FieldType.STRING
  def isPointer(self): # 
    return self.typename == FieldType.POINTER
  def isZeroes(self): # 
    return self.typename == FieldType.ZEROES
  def isByteArray(self): # 
    return self.typename == FieldType.ARRAY
  def isInteger(self): # 
    return self.typename == FieldType.INTEGER or self.typename == FieldType.SMALLINT

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
      #log.debug('STRING: Found a string "%s"/%d for encoding %s, field %s'%( repr(self.value), self.size, self.encoding, self))
      return True

  def checkPointer(self):
    value = struct.unpack('L',self.struct.bytes[self.offset:self.offset+Config.WORDSIZE])[0] #TODO biteorder
    log.debug('checkPointer offset:%s value:%s'%(self.offset, hex(value)))
    # TODO check if pointer value is in range of mappings and set self.comment to pathname value of pointer
    if value in self.struct.mappings:
      self.value = value
      self.size = Config.WORDSIZE
      self.comment = self.struct.mappings.getMmapForAddr(self.value).pathname
      return True
    else:
      return False
  
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
    start = len(bytes)
    if start < 4:
      log.debug('ENDING: bytes are %d long'%(start))
      return False
    log.debug('ENDING: range(len(bytes)-Config.WORDSIZE,-1,-Config.WORDSIZE): %s'%(len(bytes)-Config.WORDSIZE))
    for i in range(len(bytes)-Config.WORDSIZE,-1,-Config.WORDSIZE):
      if struct.unpack('L',bytes[i:i+Config.WORDSIZE])[0] == 0: 
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

  def checkEndingZeroes2(self):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    for i in range(len(bytes)-1,-1,-1):
      if bytes[i] != '\x00' :
        break
    if i == 0:
      self.value = bytes
      return True
    elif i < len(bytes) - 4 : # at least 4 byte, or it would be an int
      log.debug('ENDING2: backwards stopping with i:%d and len bytes:%d for size:%d'%(i, len(bytes), len(bytes) - 1 - i))
      self.size = len(bytes) - 1 - i
      self.value = bytes[-self.size:]
      self.offset = self.offset+( len(bytes)-i)
      log.debug('ENDING2: zerroes from offset %d:%d'%(self.offset,self.offset+self.size))
      return True
    return False

  def checkContainsZeroes(self):
    bytes = self.struct.bytes[self.offset:self.offset+self.size]    
    size = len(bytes)
    if size <= 11:
      return False
    maxOffset = size - Config.WORDSIZE
    # align offset
    it = itertools.dropwhile( lambda x: (x%Config.WORDSIZE != 0) , xrange(0, maxOffset) )
    aligned = it.next() # not exceptionnable here
    it = itertools.dropwhile( lambda x: (struct.unpack('L',bytes[x:x+Config.WORDSIZE])[0] != 0)  , xrange(aligned, maxOffset, Config.WORDSIZE) )
    try: 
      start = it.next()
    except StopIteration,e:
      return False
    it = itertools.takewhile( lambda x: (struct.unpack('L',bytes[x:x+Config.WORDSIZE])[0] == 0)  , xrange(start, maxOffset, Config.WORDSIZE) )
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

  def checkByteArray(self):
    # this should be last resort
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < 4:
      return False
    ctr = collections.Counter(bytes)
    floor = max(1,int(size*.1))
    #commons = [ c for c,nb in ctr.most_common() if nb > 2 ]
    commons = ctr.most_common()
    if len(commons) > floor:
      return False # too many different values
    # few values. it migth be an array
    self.size = size
    self.values = bytes
    self.setName('%s_%d'%(self.typename.basename, self.offset))
    return True
        

  def checkSmallInt(self):
    # TODO
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < 4:
      return False
    val = struct.unpack('L',bytes[:Config.WORDSIZE])[0] 
    if val < 0xff:
      self.value = val
      self.size = 4
      self.setName('%s_%d'%(self.typename.basename, self.offset))
      return True
    else:
      return False
    
  def decodeType(self):
    if self.decoded:
      return self.typename
    if self.typename != FieldType.UNKNOWN:
      raise TypeError('I wont coherce this Field if you think its another type')
    # try all possible things
    if self.checkString(): # Found a new string...
      self.typename = FieldType.STRING
    elif self.checkLeadingZeroes():
      log.debug ('ZERO: decoded a zeroes START padding from offset %d:%d'%(self.offset,self.offset+self.size))
      self.typename = FieldType.ZEROES
    elif self.checkEndingZeroes():
      log.debug ('ZERO: decoded a zeroes ENDING padding from offset %d:%d'%(self.offset,self.offset+self.size))
      self.typename = FieldType.ZEROES
    elif self.checkContainsZeroes():
      log.debug ('ZERO: decoded a zeroes CONTAINS padding from offset %d:%d'%(self.offset,self.offset+self.size))
      self.typename = FieldType.ZEROES
    elif self.checkPointer():
      log.debug ('POINTER: decoded a pointer to %s from offset %d:%d'%(self.comment, self.offset,self.offset+self.size))
      self.typename = FieldType.POINTER
    elif self.checkSmallInt():
      log.debug ('INTEGER: decoded an int from offset %d:%d'%(self.offset,self.offset+self.size))
      self.typename = FieldType.INTEGER
    elif self.checkByteArray():
      self.typename = FieldType.ARRAY
    else:
      # check other types
      self.decoded = False
      return None
    # typename is good
    self.decoded = True
    return self.typename
  
  def setCTypes(self, name):
    self.ctypes = name
  
  def getCTypes(self):
    if hasattr(self, 'ctypes'):
      return self.ctypes
    if self.isString() or self.isZeroes() or self.isByteArray():
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
    return hash(self.tuple())
      
  def tuple(self):
    return (self.offset, self.size, self.typename)

  def __cmp__(self, other):
    if not isinstance(other, Field):
      raise TypeError
    return cmp(self.tuple(), other.tuple())

  def __len__(self):
    return int(self.size) ## some long come and goes

  def __str__(self):
    return 'offset:%d size:%s'%(self.offset, self.size)
    
  def _getValue(self, maxLen):
    if len(self) == 0:
      return '<-haystack no pattern found->'
    if self.isString():
      bytes = repr(self.value)
    elif self.isInteger():
      return struct.unpack('L',(self.struct.bytes[self.offset:self.offset+len(self)]) )[0]
    elif self.isZeroes() or self.padding:
      bytes = repr(self.struct.bytes[self.offset:self.offset+len(self)])
    else:
      return self.value
    bl = len(bytes)
    if bl >= maxLen:
      bytes = bytes[:maxLen]+'...'
    return bytes
  
  def getSignature(self):
    return self.typename.sig
  
  def toString(self, prefix):
    if self.isPointer():
      comment = '# @ %lx %s %s'%( self.value, self.comment, self.usercomment ) 
    elif self.isInteger():
      comment = '#  %s %s %s'%( self._getValue(Config.WORDSIZE), self.comment, self.usercomment ) 
    else:
      #if self.isString() or self.padding:
      comment = '# %s %s bytes:%s'%( self.comment, self.usercomment, self._getValue(64) ) 
          
    fstr = "%s( '%s' , %s ), %s\n" % (prefix, self.getName(), self.getCTypes(), comment) 
    return fstr
    


def search(opts):
  #
  make(opts)
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-progressive', description='Do a iterative pointer search to find structure.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('dumpfiles', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.', nargs='*')
  #rootparser.add_argument('dumpfile2', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('dumpfile3', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  rootparser.set_defaults(func=search)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)

  level=logging.INFO
  if opts.debug :
    level=logging.DEBUG
  logging.basicConfig(level=level)  
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)

  opts.func(opts)


if __name__ == '__main__':
  main(sys.argv[1:])
