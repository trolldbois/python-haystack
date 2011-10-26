#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module holds some basic utils function.
'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import numpy
import os
import array

from haystack.config import Config

log = logging.getLogger('utils')

def int_array_cache(filename):
  if os.access(filename,os.F_OK):
    # load
    f = file(filename,'r')
    nb = os.path.getsize(f.name)/4 # simple TODO 
    my_array = array.array('L')
    my_array.fromfile(f,nb)
    return my_array
  return None

def int_array_save(filename, lst):
  my_array = array.array('L')
  my_array.extend(lst)
  my_array.tofile(file(filename,'w'))
  return my_array


def closestFloorValueNumpy(val, lst):
  ''' return the closest previous value to where val should be in lst (or val)
   please use numpy.array for lst
  ''' 
  indicetab = numpy.searchsorted(lst, [val])
  ind = indicetab[0]
  i = max(0,ind-1)
  return lst[i], i

def closestFloorValueOld(val, lst):
  ''' return the closest previous value to val in lst '''
  if val in lst:
    return val, lst.index(val)
  prev = lst[0]
  for i in xrange(1, len(lst)-1):
    if lst[i] > val:
      return prev, i-1
    prev = lst[i]
  return lst[-1], len(lst)-1

closestFloorValue = closestFloorValueNumpy
  

def dequeue(addrs, start, end):
  ''' 
  dequeue address and return vaddr in interval ( Config.WORDSIZE ) from a list of vaddr
  dequeue addrs from 0 to start.
    dequeue all value between start and end in retval2
  return remaining after end, retval2
  '''
  ret = []
  while len(addrs)> 0  and addrs[0] < start:
    addrs.pop(0)
  while len(addrs)> 0  and addrs[0] >= start and addrs[0] <= end - Config.WORDSIZE:
    ret.append(addrs.pop(0))
  return addrs, ret

def getHeapPointers(dumpfilename, mappings):
  ''' Search Heap pointers values in stack and heap.
      records values and pointers address in heap.
  '''
  import signature
  
  F_VALUES = Config.getCacheFilename(Config.CACHE_HS_POINTERS_VALUES, dumpfilename)
  F_ADDRS = Config.getCacheFilename(Config.CACHE_HEAP_ADDRS, dumpfilename)
  log.debug('reading from %s'%(F_VALUES))
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
    log.info('\t[-] we have %d unique pointers values out of %d orig.'%(len(values), len(heap_values)+len(stack_values)) )
  else:
    log.info('[+] Loading from cache')
    log.info('\t[-] we have %d unique pointers values, and %d pointers in heap .'%(len(values), len(heap_addrs)) )
  aligned = filter(lambda x: (x%4) == 0, values)
  not_aligned = sorted( set(values)^set(aligned))
  log.info('\t[-] only %d are aligned values.'%(len(aligned) ) )
  return values,heap_addrs, aligned, not_aligned

