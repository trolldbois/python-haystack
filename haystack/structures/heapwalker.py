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
    self._init_heap()
  
  def _init_heap(self):
    raise NotImplementedError('Please implement all methods')

  def get_user_allocations(self):
    ''' returns all User allocations (addr,size) '''
    raise NotImplementedError('Please implement all methods')

  def get_free_chunks(self):
    ''' returns all free chunks in the heap (addr,size) '''
    raise NotImplementedError('Please implement all methods')
  
  
# TODO make a virtual function that plays libc or win32 ?
# or put that in the MemoryMappings ?
# or in the context ?
 
def detect_heap_walker(mappings):
    """try to find what type of heaps are """
    if not instance(mappings, lst):
        raise TypeError('Feed me a list')
    # try to orient the guessing
    linux = winxp = win7 = 0
    for pathname in [m.pathname.lower() for m in self.mappings if m.pathname is not None]:
         if '\\system32\\' in pathname:
            winxp += 1
            win7 += 1
         if 'ntdll.dll' in pathname:
            winxp += 1
            win7 += 1
         elif 'Documents and Settings' in pathname:
            winxp += 1
         elif 'xpsp2res.dll' in pathname:
            winxp += 1
         elif 'SysWOW64' in pathname:
            win7 += 1
         elif '\\wer.dll' in pathname:
            win7 += 1
         elif '[heap]' in pathname:
            linux += 1
         elif '[vdso]' in pathname:
            linux += 1
         elif '/usr/lib/' in pathname:
            linux += 1
         elif '/' == pathname[0]:
            linux += 1
    print 'scores', linux, winxp, win7
    # TODO fight for cpu arch ?
    scores = max(linux,max(winxp,win7))
    if scores == linux:
        from haystack.structures.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder()
    elif scores == winxp:
        from haystack.structures.win32 import winheapwalker
        return winheapwalker.WinHeapFinder()
    else:
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder()


class WinHeapFinder(object):
    def __init__(self):
        self.heap_type = None
        raise NotImplementedError('Please fix your self.heap_type')

    def is_heap(self, mappings, mapping):
        """test if a mapping is a heap"""
        heap = self.read_heap(mapping)
        load = heap.loadMembers(mappings, 1) # need to go 3 to load all.
        return load

    def read_heap(self, mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        addr = mapping.start
        heap = mapping.readStruct( addr, self.heap_type )
        return heap

    def get_heaps(self, mappings):
        """return the list of mappings that load as heaps"""
        if not instance(mappings, lst):
            raise TypeError('Feed me a list of mappings') 
        heaps = []
        for mapping in mappings:
            addr = mapping.start
            heap = self.read_heap(mapping)
            load = heap.loadMembers(mappings, 1) # first level validation
            if load:
                heaps.append(heap)
        heaps.sort(key=lambda m: self.read_heap(m).ProcessHeapsListIndex)
        return heaps



