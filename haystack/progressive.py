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

from utils import xrange
from cache_utils import int_array_cache,int_array_save
import memory_dumper
import signature 
from pattern import Config

log = logging.getLogger('progressive')


def make(opts):
  log.info('Extracting structures from pointer values and offsets.')
  ## get the list of pointers values pointing to heap
  ## need cache
  mappings = memory_dumper.load( opts.dumpfile, lazy=True)  
  values,heap_addrs, aligned = getHeapPointers(opts.dumpfile.name, mappings)
  # we
  if not os.access(Config.structsCacheDir, os.F_OK):
    os.mkdir(Config.structsCacheDir )
  heap = mappings.getHeap()
  # creates
  for anon_struct in buildAnonymousStructs(heap, aligned, heap_addrs):
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
  log.info('  only %d are aligned values.'%(len(aligned) ) )
  return values,heap_addrs, aligned

def buildAnonymousStructs(heap, values, p_addrs):
  ''' values: pointer values
  '''
  lengths=[]
  for i in range(len(values)-1):
    lengths.append(values[i+1]-values[i])
  lengths.append(heap.end-values[-1]) # add tail
  
  addrs = list(p_addrs)
  # make AnonymousStruct
  for i in range(len(values)):
    start = values[i]
    size = lengths[i]
    addrs, my_pointers_addrs = dequeue(addrs, start, start+size)
    anon = AnonymousStructInstance(values[i], heap.readBytes(start, size) )
    log.debug('Created a struct with %d pointers fields'%( len(my_pointers_addrs) ))
    # get pointers addrs in start -> start+size
    for p_addr in my_pointers_addrs:
      anon.setField(p_addr, Config.WORDSIZE, 'ctypes.c_void_p')
    yield anon
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
  
  def setField(self, vaddr, size, typename):
    offset = vaddr - self.vaddr
    if offset < 0 or offset > len(self):
      return IndexError()
    field = (offset, size, typename)
    self._check(field)
    self.fields.append(field)
    self.fields.sort()
    return 

  def save(self):
    self.fname = os.path.sep.join([Config.structsCacheDir, self.name()])
    pickle.dump(self, file(self.fname,'w'))
    return
  
  def name(self):
    return 'AnonymousStruct_%s_%s_%s'%(len(self), self.prefixname, len(self.fields) )
  
  def _check(self,field):
    # TODO check against other fields
    return
  def __getitem__(self, i):
    return self.fields[i]
  def __len__(self):
    return len(self.bytes)

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
