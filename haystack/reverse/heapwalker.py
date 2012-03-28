#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

class HeapWalker(object):
  def __init__(self, mappings, mapping, offset=0):
    self._mappings = mappings
    self._mapping = mapping
    self._offset = offset
    self._initHeap()
  
  def _initHeap(self):
    raise NotImplementedError('Please implement all methods')

  def getUserAllocations(self):
    ''' returns all User allocations (addr,size) '''
    raise NotImplementedError('Please implement all methods')
  
  
# TODO make a virtual function that plays libc or win32 ?
# or put that in the MemoryMappings ?
# or in the context ?
 

