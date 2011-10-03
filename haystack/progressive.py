#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, os, pickle, time, sys
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


def make(opts):
  log.info('Extracting structures from pointer values and offsets.')
  ## get the list of pointers values pointing to heap
  ## need cache
  mappings = memory_dumper.load( opts.dumpfile, lazy=True)  
  values,heap_addrs, aligned, not_aligned = getHeapPointers(opts.dumpfile.name, mappings)
  # we
  if not os.access(Config.structsCacheDir, os.F_OK):
    os.mkdir(Config.structsCacheDir )
  heap = mappings.getHeap()
  # creates
  anons = []
  for anon_struct in buildAnonymousStructs(heap, aligned, not_aligned, heap_addrs):
    #anon_struct.save()
    # TODO regexp search on structs/bytearray.
    # regexp could be better if crossed against another dump.
    #
    #log.info(anon_struct.toString())
    anons.append(anon_struct)
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
    log.info('Loading from cache')
    log.info('we have %d unique pointers values, and %d pointers in heap .'%(len(values), len(heap_addrs)) )
  aligned = filter(lambda x: (x%4) == 0, values)
  not_aligned = sorted( set(values)^set(aligned))
  log.info('  only %d are aligned values.'%(len(aligned) ) )
  return values,heap_addrs, aligned, not_aligned

def buildAnonymousStructs(heap, aligned, not_aligned, p_addrs):
  ''' values: ALIGNED pointer values
  '''
  lengths=[]
  for i in range(len(aligned)-1):
    lengths.append(aligned[i+1]-aligned[i])
  lengths.append(heap.end-aligned[-1]) # add tail
  
  addrs = list(p_addrs)
  unaligned = list(not_aligned)
  nbMembers = 0
  # make AnonymousStruct
  for i in range(len(aligned)):
    hasMembers=False
    start = aligned[i]
    size = lengths[i]
    # the pointers field address/offset
    addrs, my_pointers_addrs = dequeue(addrs, start, start+size)
    # the pointers values, that are not aligned
    unaligned, my_unaligned_addrs = dequeue(unaligned, start, start+size)
    ### read the struct
    anon = AnonymousStructInstance(aligned[i], heap.readBytes(start, size) )
    ##log.debug('Created a struct with %d pointers fields'%( len(my_pointers_addrs) ))
    # get pointers addrs in start -> start+size
    for p_addr in my_pointers_addrs:
      f = anon.setField(p_addr, Field.POINTER, Config.WORDSIZE)
      if f is not None:
        f.setComment('') # target struct ?
    ## set field for unaligned pointers, that sometimes gives good results ( char[][] )
    for p_addr in my_unaligned_addrs:
      if anon.setField(p_addr) is not None: #, Field.UKNOWN):
        nbMembers+=1
        hasMembers=True
      # not added
    # try to decode fields
    anon.decodeFields()
    # debug
    if hasMembers:
      for _f in anon.fields:
        if _f.size == -1:
          log.debug('ERROR, %s '%(_f))
      log.debug('Created a struct %s with %d fields'%( anon, len(anon.fields) ))
      log.debug(anon.toString())
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
  def __init__(self, vaddr, bytes, prefix=None):
    self.vaddr = vaddr
    self.bytes = bytes
    self.fields = []
    if prefix is None:
      self.prefixname = str(self.vaddr)
    else:
      self.prefixname = '%s_%s'%(self.vaddr, self.prefix)
    self.resolved = False
    return
  
  def setField(self, vaddr, typename=None, size=-1, padding=False ):
    offset = vaddr - self.vaddr
    if offset < 0 or offset > len(self):
      raise IndexError()
    if typename is None:
      typename = Field.UNKNOWN
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
    if typename == Field.UNKNOWN:
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

  def save(self):
    self.fname = os.path.sep.join([Config.structsCacheDir, str(self)])
    pickle.dump(self, file(self.fname,'w'))
    return
  
  def __str__(self):
    return 'AnonymousStruct_%s_%s_%s'%(len(self), self.prefixname, len(self.fields) )
  
  def _check(self,field):
    # TODO check against other fields
    return field.check()
  
  def decodeFields(self):
    self._fixGaps()
    paddings = [ f for f in self.fields if f.padding ] # clean paddings to check new fields
    newfields=[]
    for p in paddings:
      log.debug('decoding unkown field %s'%(p))
      paddingSize = len(p)
      # detect if nul-terminated string
      field = Field(self, p.offset, Field.UNKNOWN, len(p), False)
      fieldType = field.decodeType()
      if fieldType is None: # Found a new field with a probable type...
        pass
      else:
        newfields.append(field) # save it

      # add gap fields to decode target        
      if len(field) == paddingSize: # padding == field, goto next padding
        continue
      elif len(field) > paddingSize:
        log.debug('Overlapping string to next Field. Aggregation needed.')
        continue
      else: # there a gap
        nextoffset = field.offset+len(field)
        paddingSize -= len(field)
        newpadding = Field(self, nextoffset, Field.UNKNOWN, paddingSize, False) # next field
        log.debug('build next field in padding %s '%(newpadding))
        paddings.append(newpadding)
    # save fields
    self.fields.extend(newfields)
    self.fields.sort()
    self._fixGaps()
    return
  
  def _fixGaps(self):
    ''' Fix this structure and populate empty offsets with default fields '''
    nextoffset = 0
    self._gaps = 0
    self.fields = [ f for f in self.fields if f.padding != True ] # clean paddings to check new fields
    myfields = sorted(self.fields)
    for f in myfields:
      if f.offset > nextoffset : # add temp padding field
        self._gaps += 1
        padding = self.makeUntyped(nextoffset, f.offset-nextoffset)
      elif f.offset < nextoffset :
        log.warning('overlapping fields at offset %d'%(f.offset))
        #TODO compare if padding or not, and resolve ?
      else: # == 
        pass
      nextoffset = f.offset + len(f)
    # conclude
    if nextoffset < len(self):
      self._gaps += 1
      padding = self.makeUntyped(nextoffset, len(self)-nextoffset)
    if self._gaps == 0:
      self.resolved = True
    return
  
  def makeUntyped(self, offset, size):
    typename = 'ctypes.c_ubyte * %d' % (size)
    padding = self.setField( self.vaddr+offset, typename, size, True)
    padding.setName('untyped_%d'%(padding.offset) )
    return padding
      
  def __getitem__(self, i):
    return self.fields[i]
  def __len__(self):
    return len(self.bytes)

  def getFieldName(self, field):
    if field.isString():
      return 'text_%s'%(field.offset) 
    if field.isZeroes():
      return 'zeroes_%s'%(field.offset) 
    return '%s_%s'%(field.typename, field.offset) # TODO
    
  def getFieldType(self, field):
    return field.typename # TODO

  def toString(self):
    self._fixGaps()
    fieldsString = '[ \n%s ]'% ( ''.join([ field.toString('\t') for field in self.fields]))
    ctypes_def = '''
class %s(LoadableMembers):
  _fields_ = %s

''' % (self, fieldsString)
    return ctypes_def


class Field:
  STRING = 'ctypes.c_char_p'
  POINTER = 'ctypes.c_void_p'
  PADDING = 'ctypes.c_ubyte'
  ZEROES = 'zeroes'
  UNKNOWN = 'unknown'
  def __init__(self, astruct, offset, typename, size, isPadding):
    self.struct = astruct
    self.offset = offset
    self.size = size
    self.typename = typename
    self.padding = isPadding
    self.typesTested = []
    self.value = None
    self.comment = ''
  
  def setComment(self, txt):
    self.comment = '# %s'%txt
  def getComment(self):
    return self.comment
    
  def isString(self): # null terminated
    return self.typename == Field.STRING
  def isPointer(self): # 
    return self.typename == Field.POINTER
  def isZeroes(self): # 
    return self.typename == Field.ZEROES

  def checkString(self):
    ''' if there is no \x00 termination, its not a string
    that means that if we have a bad pointer in the middle of a string, 
    the first part will not be understood as a string'''
    bytes = self.struct.bytes[self.offset:]
    ret = re_string.startsWithNulTerminatedString(bytes)
    if not ret:
      self.typesTested.append(Field.STRING)
      #log.warning('STRING: This is not a string %s'%(self))
      return False
    else:
      self.size, self.encoding, self.value = ret 
      self.value += '\x00' # null terminated
      self.size += 1 # null terminated
      log.debug('STRING: Found a string "%s"/%d for encoding %s, field %s'%( repr(self.value), self.size, self.encoding, self))
      return True

  def checkPointer(self):
    self.value = struct.unpack('L',self.struct.bytes[self.offset:self.offset+self.size])[0] #TODO biteorder
    # TODO check if pointer value is in range of mappings
    return True
  
  def checkLeadingZeroes(self):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    previous = -1
    for i, val in enumerate(bytes):
      if (self.offset+i) % Config.WORDSIZE == 0: # aligned word
        previous = i
      if val != 0:  # ah ! its not null !
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
      log.debug('ZERO: ALL zeroes ')
      # self.size = i # change is not necessary
      self.value = bytes
      return True
    return False

  def checkEndingZeroes(self):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    for i in range(self.size-1,-1,-1):
      if bytes[i] != 0 :
        break
    if i == 0:
      self.value = bytes
      return True
    elif i < self.size - 1 : # at least 1 byte
      self.size = self.size - 1 - i
      self.value = bytes[-self.size:]
      return True
    return False

  def checkContainsZeroes(self):
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    it = itertools.dropwhile( lambda x: bytes[x] != 0 , xrange(0,self.size) )
    try: 
      start = it.next()
    except StopIteration,e:
      return False
    it = itertools.takewhile( lambda x: bytes[x] == 0 , xrange(start,self.size) )
    end = max(it)
    size = end-start
    if size < 1:
      return False
    self.size = size
    self.value = bytes[start:end]    
    self.offset = self.offset+start
    return True

  
  def check(self):
    if self.isString() and self.value is None:
      return self.checkString()
    elif self.isPointer() and self.value is None:
      return self.checkPointer()
    return True
  
  def decodeType(self):
    if self.typename != Field.UNKNOWN:
      raise TypeError('I wont coherce this Field if you think its another type')
    # try all possible things
    if self.checkString(): # Found a new string...
      log.debug ('STRING: decoded a string field')
      self.typename = Field.STRING
      return Field.STRING
    elif self.checkLeadingZeroes():
      log.debug ('ZERO: decoded a zeroes START padding')
      self.typename = Field.ZEROES
      return Field.ZEROES
    elif self.checkEndingZeroes():
      log.debug ('ZERO: decoded a zeroes ENDING padding')
      self.typename = Field.ZEROES
      return Field.ZEROES
    elif self.checkContainsZeroes():
      log.debug ('ZERO: decoded a zeroes padding inside')
      self.typename = Field.ZEROES
      return Field.ZEROES
    pass # check other types
    return None

  
  def getCTypes(self):
    if hasattr(self, 'ctypes'):
      return self.ctypes
    return self.struct.getFieldType(self)
  
  def setName(self, name):
    self.name = name
  
  def getName(self):
    if hasattr(self, 'name'):
      return self.name
    return self.struct.getFieldName(self)
      
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
    elif self.padding:
      bytes = repr(self.struct.bytes[self.offset:self.offset+len(self)])
    elif self.isZeroes():
      bytes = repr(self.struct.bytes[self.offset:self.offset+len(self)])
    bl = len(bytes)
    if bl >= maxLen:
      bytes = bytes[:maxLen]+'...'
    return bytes
    
  def toString(self, prefix):
    comment = self.comment
    if self.isString() or self.padding:
      comment = '# %s bytes:%s'%( self.comment, self._getValue(64) ) 
    elif self.isPointer():
      comment = '# @0x%lx %s'%( self.value, self.comment ) 
          
    fstr = "%s( %s , %s ), %s\n" % (prefix, self.getName(), self.getCTypes(), comment) 
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
