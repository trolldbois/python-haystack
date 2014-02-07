#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import sys

import numpy 
from haystack import model
from haystack.structures import heapwalker
from haystack.structures.libc import ctypes_malloc

log=logging.getLogger('libcheapwalker')


class LibcHeapWalker(heapwalker.HeapWalker):
    """ """
    def _init_heap(self):
        log.debug('+ Heap @%x size: %d # %s'%(self._mapping.start+self._offset, len(self._mapping), self._mapping) )
        self._allocs = None
        self._free_chunks = None

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) and only the user writeable part.
        addr and size EXCLUDES the HEAP_ENTRY header.
        """
        if self._allocs is None:
            self._set_chunk_lists()
        return self._allocs

    def get_free_chunks(self):
        """ returns all free chunks that are not allocated (addr,size) .
                addr and size EXCLUDES the HEAP_ENTRY header.
        """
        if self._free_chunks is None:
            self._set_chunk_lists()
        return self._free_chunks

    def _set_chunk_lists(self):
        self._allocs, self._free_chunks = ctypes_malloc.get_user_allocations(self._mappings, self._mapping)


class LibcHeapFinder(heapwalker.HeapFinder):
    def __init__(self):
        self.heap_type = ctypes_malloc.malloc_chunk
        self.walker_class = LibcHeapWalker
        self.heap_validation_depth = 20

    def get_heap_mappings(self, mappings):
        """Prioritize heaps with [heap]"""
        heap_mappings = super(LibcHeapFinder,self).get_heap_mappings(mappings)
        i = [i for (i,m) in enumerate(heap_mappings) if m.pathname == '[heap]']
        if len(i) == 1:
            h = heap_mappings.pop(i[0])
            heap_mappings.insert(0, h)
        return heap_mappings




