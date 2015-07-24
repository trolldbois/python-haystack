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
from haystack import types

from haystack.structures import heapwalker

import ctypes

log = logging.getLogger('winheapwalker')


class WinHeapWalker(heapwalker.HeapWalker):

    """
    Helpers functions that return pure python lists - no ctypes in here.

    Backend allocation in BlocksIndex
    FTH allocation in Heap.LocalData[n].SegmentInfo.CachedItems
    Virtual allocation
    """

    def _init_heap(self):
        self._allocs = None
        self._free_chunks = None
        self._child_heaps = None
        # clean the iport module to remove any rpevious loading with a different
        # ctypes proxy class
        #if 'winheap' in sys.modules:
        #    del sys.modules['winheap']
        #import ctypes
        from haystack.structures.win32 import winheap
        self._heap = self._mapping.read_struct(
            self._mapping.start +
            self._offset,
            winheap.HEAP)
        if not self._heap.load_members(self._memory_handler, 1):
            raise TypeError('HEAP.load_members returned False')

        log.debug('+ Heap @%0.8x size: %d # %s' %
                  (self._mapping.start +
                   self._offset, len(self._mapping), self._mapping))
        # print '+ Heap @%0.8x size:%d FTH_Type:0x%x maskFlag:0x%x index:0x%x'%(self._mapping.start+self._offset,
        #                            len(self._mapping), self._heap.FrontEndHeapType, self._heap.EncodeFlagMask, self._heap.ProcessHeapsListIndex)
        # placeholders
        self._backend_committed = None
        self._backend_free = None
        self._fth_committed = None
        self._fth_free = None
        self._valloc_committed = None
        self._valloc_free = None
        return

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
        from haystack.structures.win32 import winheap
        sublen = ctypes.sizeof(winheap.HEAP_ENTRY)
        # get all chunks
        vallocs, va_free = self._get_virtualallocations()
        chunks, free_chunks = self._get_chunks()
        fth_chunks, fth_free = self._get_frontend_chunks()

        # make the user allocated list
        lst = vallocs + chunks + fth_chunks
        myset = set([(addr + sublen, size - sublen) for addr, size in lst])
        if len(lst) != len(myset):
            log.warning(
                'NON unique referenced user chunks found. Please enquire. %d != %d' %
                (len(lst), len(myset)))
        # need to cut sizeof(HEAP_ENTRY) from address and size
        self._allocs = numpy.asarray(sorted(myset))

        free_lists = self._get_freelists()
        lst = va_free + free_chunks + fth_free
        # free_lists == free_chunks.
        # fth_free is part of 1 chunk of allocated chunks.
        # FIXME: va_free I have no freaking idea.
        myset = set([(addr + sublen, size - sublen) for addr, size in lst])
        if len(free_chunks) != len(free_lists):
            log.warning('Weird: len(free_chunks) != len(free_lists)')
        # need to cut sizeof(HEAP_ENTRY) from address and size
        self._free_chunks = numpy.asarray(sorted(myset))
        return

    def get_heap_children_mmaps(self):
        """ use free lists to establish the hierarchy between mmaps"""
        # FIXME: we should use get_segmentlist to coallescce segment in one heap
        # memory mapping. Not free chunks.
        # heap.get_segment_list.
        if self._child_heaps is None:
            child_heaps = set()
            for x, s in self._get_freelists():
                m = self._memory_handler.get_mapping_for_address(x)
                if (m != self._mapping) and (m not in child_heaps):
                    log.debug(
                        'mmap 0x%0.8x is extended heap space from 0x%0.8x' %
                        (m.start, self._mapping.start))
                    child_heaps.add(m)
                    pass
            self._child_heaps = child_heaps
        # TODO: add information from used user chunks
        return self._child_heaps

    def _get_virtualallocations(self):
        """ returns addr,size of committed,free vallocs heap entries"""
        if (self._valloc_committed, self._valloc_free) == (None, None):
            self._valloc_committed = self._heap.get_virtual_allocated_blocks_list(
                self._memory_handler)
            self._valloc_free = []  # FIXME TODO
            log.debug(
                '\t+ %d vallocated blocks' %
                (len(
                    self._valloc_committed)))
            # for block in allocated: #### BAD should return (vaddr,size)
            #    log.debug( '\t\t- vallocated commit %x reserve %x @%0.8x'%(block.CommitSize, block.ReserveSize, ctypes.addressof(block)))
            #
        return self._valloc_committed, self._valloc_free

    def _get_chunks(self):
        """ returns addr,size of committed,free heap entries in blocksindex"""
        if (self._backend_committed, self._backend_free) == (None, None):
            self._backend_committed, self._backend_free = self._heap.get_chunks(
                self._memory_handler)
            # HEAP_ENTRY.Size is in chunk size. (8 bytes )
            allocsize = sum([c[1] for c in self._backend_committed])
            freesize = sum([c[1] for c in self._backend_free])
            log.debug('\t+ Segment Chunks: alloc: %0.4d [%0.5d B] free: %0.4d [%0.5d B]' % (
                len(self._backend_committed), allocsize, len(self._backend_free), freesize))
            #
            # for chunk in allocated:
            #    log.debug( '\t\t- chunk @%0.8x size:%d'%(chunk[0], chunk[1]) )
        return self._backend_committed, self._backend_free

    def _get_frontend_chunks(self):
        """ returns addr,size of committed,free heap entries in fth heap"""
        if (self._fth_committed, self._fth_free) == (None, None):
            self._fth_committed, self._fth_free = self._heap.get_frontend_chunks(
                self._memory_handler)
            fth_commitsize = sum([c[1] for c in self._fth_committed])
            fth_freesize = sum([c[1] for c in self._fth_free])
            log.debug(
                '\t+ %d frontend chunks, for %d bytes' %
                (len(
                    self._fth_committed),
                    fth_commitsize))
            log.debug(
                '\t+ %d frontend free chunks, for %d bytes' %
                (len(
                    self._fth_free),
                    fth_freesize))
            #
            # for chunk in fth_chunks:
            #    log.debug( '\t\t- fth_chunk @%0.8x size:%d'%(chunk[0], chunk[1]) )
        return self._fth_committed, self._fth_free

    def _get_freelists(self):
        # FIXME check if freelists and committed backend collides.
        free_lists = [
            (freeblock_addr,
             size) for freeblock_addr,
            size in self._heap.get_freelists(
                self._memory_handler)]
        freesize = sum([c[1] for c in free_lists])
        log.debug(
            '\t+ freeLists: free: %0.4d [%0.5d B]' %
            (len(free_lists), freesize))
        return free_lists

    def _get_BlocksIndex(self):
        pass


class WinHeapFinder(heapwalker.HeapFinder):

    # FIXME load unload ctypes
    def _init_heap_type(self):
        from haystack.structures.win32 import winheap
        winheap = reload(winheap)
        return winheap.HEAP

    def _init_heap_validation_depth(self):
        return 1

    def get_heap_mappings(self):
        """return the list of _memory_handler that load as heaps"""
        heap_mappings = super(WinHeapFinder, self).get_heap_mappings()
        # FIXME PYDOC  cant remember why we do this.
        for mapping in heap_mappings:
            mapping._children = WinHeapWalker(
                self._memory_handler,
                mapping).get_heap_children_mmaps()
        heap_mappings.sort(
            key=lambda m: self._read_heap(m).ProcessHeapsListIndex)
        return heap_mappings

    def get_heap_walker(self, heap):
        raise NotImplementedError(self)
