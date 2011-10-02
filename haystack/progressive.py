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
  for anon_struct in buildAnonymousStructs(heap, aligned, not_aligned, heap_addrs):
    #anon_struct.save()
    # TODO regexp search on structs/bytearray.
    # regexp could be better if crossed against another dump.
    #
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
  stringfields= 0
  # make AnonymousStruct
  for i in range(len(aligned)):
    inlineString=False
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
      anon.setField(p_addr, Field.POINTER, Config.WORDSIZE)
    ## set field for unaligned pointers, that sometimes gives good results ( char[][] )
    for p_addr in my_unaligned_addrs:
      if anon.setField(p_addr, Field.STRING):
        stringfields+=1
        inlineString=True
    # debug
    if inlineString:
      log.debug('Created a struct %s with %d fields: %s'%( anon, len(anon.fields), anon.toString() ))
    yield anon
  log.info('Typed %d stringfields'%(stringfields))
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
    return
  
  def setField(self, vaddr, typename, size=0, padding=False ):
    offset = vaddr - self.vaddr
    if offset < 0 or offset > len(self):
      return IndexError()
    field = Field(self, offset, typename, size, padding)
    if not self._check(field):
      return False
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

  def _fix(self):
    ''' Fix this structure and populate empty offsets with default fields '''
    nextoffset = 0
    myfields = sorted(self.fields)
    for f in myfields:
      if f.offset > nextoffset :
        # add padding field
        padding = self.makePadding(nextoffset, f.offset-nextoffset)
        nextoffset = f.offset + len(f)
      elif f.offset < nextoffset :
        log.debug('overlapping fields at offset %d'%(f.offset))
        #TODO compare if padding or not, and resolve ?
      else: # == 
        nextoffset = f.offset+len(f)
        pass
    if nextoffset < len(self):
      padding = self.makePadding(nextoffset, len(self)-nextoffset)
    return
  
  def makePadding(self, offset, size):
    typename = 'ctypes.c_ubyte * %d' % (size)
    padding = self.setField( self.vaddr+offset, typename, size, True)
    padding.setName('padding_%d'%(padding.offset) )
    return padding
      
  def __getitem__(self, i):
    return self.fields[i]
  def __len__(self):
    return len(self.bytes)

  def getFieldName(self, field):
    return '%s_%s'%(field.typename, field.offset) # TODO
    
  def getFieldType(self, field):
    return field.typename # TODO

  def toString(self):
    self._fix()
    fieldsString = '[ \n%s ]'% ( ''.join([ field.toString('\t') for field in self.fields]))
    ctypes_def = '''
class %s(LoadableMembers):
  _fields_ = %s

''' % (self, fieldsString)
    return ctypes_def


class Field:
  STRING = 'ctypes.c_char_p'
  POINTER = 'ctypes.c_void_p'
  def __init__(self, astruct, offset, typename, size, isPadding):
    self.struct = astruct
    self.offset = offset
    self.size = size
    self.typename = typename
    self.padding = isPadding
    self.typesTested = []
    self.value = None
    self.comment = '%s'%(self)
  
  def setComment(self, txt):
    self.comment = '# %s'%txt
  def getComment(self):
    return self.comment
    
  def isString(self): # null terminated
    return self.typename == Field.STRING
  def isPointer(self): # null terminated
    return self.typename == Field.POINTER

  def checkString(self):
    ''' if there is no \x00 termination, its not a string
    that means that if we have a bad pointer in the middle of a string, 
    the first part will not be understood as a string'''
    bytes = self.struct.bytes[self.offset:]
    ret = re_string.startsWithNulTerminatedString(bytes)
    if not ret:
      self.typename = None
      self.typesTested.append(Field.STRING)
      return False
    else:
      self.size, self.encoding, self.value = ret 
      self.value+='\x00'
      log.debug('Found a string "%s"/%d for encoding %s, field size %d'%(self.value, self.size, self.encoding, len(self)))
      return True

  def checkPointer(self):
    self.value = struct.unpack('L',self.struct.bytes[self.offset:self.offset+self.size])
    return True
    
  def check(self):
    if self.isString() and self.value is None:
      return self.checkString()
    elif self.isPointer() and self.value is None:
      return self.checkPointer()
    return True
  
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
    return self.size

  def __str__(self):
    return 'size:%d'%(len(self))
    
  def getBytes(self):
    if len(self) == 0:
      return '<-haystack no pattern found->'
    return self.struct.bytes[self.offset:len(self)]
    
  def toString(self, prefix):
    comment = self.comment
    if self.isString():
      comment = '# %s str:%s...'%( self.comment, self.value[:20] ) 
    elif self.padding :
      comment = '# %s pad:%s...'%( self.comment, repr(self.getBytes()[:20]) )
          
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
