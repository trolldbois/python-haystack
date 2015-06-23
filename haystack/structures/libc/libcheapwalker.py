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

log = logging.getLogger('libcheapwalker')


class LibcHeapWalker(heapwalker.HeapWalker):

    """ """

    def _init_heap(self):
        log.debug('+ Heap @%x size: %d # %s' %
                  (self._mapping.start +
                   self._offset, len(self._mapping), self._mapping))
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
        from haystack.structures.libc import ctypes_malloc
        self._allocs, self._free_chunks = ctypes_malloc.get_user_allocations(
            self._mappings, self._mapping)


class LibcHeapFinder(heapwalker.HeapFinder):

    def __init__(self):
        import ctypes
        from haystack.structures.libc import ctypes_malloc
        ctypes_malloc = reload(ctypes_malloc)
        self.heap_type = ctypes_malloc.malloc_chunk
        self.walker_class = LibcHeapWalker
        self.heap_validation_depth = 20

    # def is_heap(self, mappings, mapping):
    #    """test if a mapping is a heap - at least one allocation."""
    #    if not super(LibcHeapFinder,self).is_heap(mappings, mapping):
    #        return False
    #    # try to get at least one alloc.
    #    from haystack.structures.libc.ctypes_malloc import iter_user_allocations
    #    for x in iter_user_allocations(mappings, mapping):
    #        return True
    #    return False

    def get_heap_mappings(self, mappings):
        """Prioritize heaps with [heap]"""
        heap_mappings = super(LibcHeapFinder, self).get_heap_mappings(mappings)
        i = [
            i for (
                i,
                m) in enumerate(heap_mappings) if m.pathname == '[heap]']
        if len(i) == 1:
            h = heap_mappings.pop(i[0])
            heap_mappings.insert(0, h)
        return heap_mappings
