# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import ctypes

from haystack.allocators import heapwalker


log = logging.getLogger('winheapwalker')


class WinHeapWalker(heapwalker.HeapWalker):
    """
    Helpers functions that return pure python lists - no ctypes in here.

    Backend allocation in BlocksIndex
    FTH allocation in Heap.LocalData[n].SegmentInfo.CachedItems
    Virtual allocation
    """

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
        """
        If its a backend, reports vallocs, _get_chunks and get_free_list
        If its a frontend,
        LAL: reports vallocs and (_get_chunks-lal) as committed
             reports lal | free_list as free
        LFH: reports vallocs and (_get_chunks-lfh_free | lfh_committed) as committed
             reports lfh_free | free_list as free
        :return:
        """
        # Backend
        vallocs = self._get_virtualallocations()
        chunks, free_chunks = self._get_chunks()
        # need to cut sizeof(HEAP_ENTRY) from address and size
        # FIXME ? why report calculation up to here ?
        sublen = ctypes.sizeof(self._heap_module.HEAP_ENTRY)
        # make the user allocated list
        lst = vallocs | chunks
        backend_allocs = set([(addr + sublen, size - sublen) for addr, size in lst])
        if len(lst) != len(backend_allocs):
            log.warning('NON unique referenced user chunks found. Please enquire. %d != %d' % (len(lst), len(backend_allocs)))

        # free_lists == free_chunks.
        if False:
            log.warning('Duplicate walking of free chunks')
            free_lists = self._get_freelists()
            backend_free_chunks = set([(addr + sublen, size - sublen) for addr, size in free_lists])
            if len(free_chunks) != len(free_lists):
                log.warning('Weird: len(free_chunks) != len(free_lists)')
        else:
            backend_free_chunks = set([(addr + sublen, size - sublen) for addr, size in free_chunks])

        # frontend too
        if self._heap.FrontEndHeapType == 0:
            self._allocs = backend_allocs
            self._free_chunks = backend_free_chunks
        else:
            front_allocs, front_free_chunks = self._get_frontend_chunks()
            # point to header
            #front_allocs2 = set([(addr + sublen, size - sublen) for addr, size in front_allocs])
            #front_free_chunks2 = set([(addr + sublen, size - sublen) for addr, size in front_free_chunks])
            # points to chunk
            front_allocs2 = set([(addr, size ) for addr, size in front_allocs])
            front_free_chunks2 = set([(addr, size) for addr, size in front_free_chunks])

            if self._heap.FrontEndHeapType == 1:
                # LAL: reports vallocs and (_get_chunks-lal) as committed
                #      reports lal | free_list as free
                # TODO + overhead
                self._allocs = backend_allocs - front_free_chunks2
                self._free_chunks = front_free_chunks2 | backend_free_chunks
            elif self._heap.FrontEndHeapType == 2:
                # LFH: reports vallocs and (_get_chunks-lfh_free | lfh_committed) as committed
                #      reports lfh_free | free_list as free
                self._allocs = backend_allocs - front_free_chunks2 | front_allocs2
                self._free_chunks = front_free_chunks2 | backend_free_chunks
        return

    def get_heap_children_mmaps(self):
        """ use free lists to establish the hierarchy between mmaps"""
        # FIXME: we should use get_segmentlist to coallescce segment in one heap
        # memory mapping. Not free chunks.
        # heap.get_segment_list.
        if self._child_heaps is None:
            child_heaps = set()
            for x, s in self._get_freelists():
                log.debug('get_heap_children_mmaps a')
                m = self._memory_handler.get_mapping_for_address(x)
                if (m != self._heap_mapping) and (m not in child_heaps):
                    # FIXME, its actually a segment isn't it ?
                    log.debug('mmap 0x%0.8x is extended heap space from 0x%0.8x',m.start, self._heap_mapping.start)
                    child_heaps.add(m)
                    pass
            self._child_heaps = list(child_heaps)
        # TODO: add information from used user chunks
        self._child_heaps.sort()
        log.debug('get_heap_children_mmaps b')
        return self._child_heaps

    def _get_virtualallocations(self):
        """ returns addr,size of committed,free vallocs heap entries"""
        if self._valloc_committed is None:
            allocs = self._validator.HEAP_get_virtual_allocated_blocks_list(self._heap)
            self._valloc_committed = set([(addr, c_size) for addr, c_size, r_size in allocs])
            log.debug('\t+ %d vallocated blocks' % len(self._valloc_committed))
        return self._valloc_committed

    def _get_chunks(self):
        """ returns addr,size of committed,free heap entries in blocksindex"""
        if (self._backend_committed, self._backend_free) == (None, None):
            self._backend_committed, self._backend_free = self._validator.get_backend_chunks(self._heap)
            # HEAP_ENTRY.Size is in chunk size. (8 bytes / 16 bytes )
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
            self._fth_committed, self._fth_free = self._validator.get_frontend_chunks(self._heap)
            fth_commitsize = sum([c[1] for c in self._fth_committed])
            fth_freesize = sum([c[1] for c in self._fth_free])
            log.debug('\t+ %d frontend chunks, for %d bytes' %(len(self._fth_committed), fth_commitsize))
            log.debug('\t+ %d frontend free chunks, for %d bytes' % (len(self._fth_free), fth_freesize))
            #
            # for chunk in fth_chunks:
            #    log.debug( '\t\t- fth_chunk @%0.8x size:%d'%(chunk[0], chunk[1]) )
        return self._fth_committed, self._fth_free

    def _get_freelists(self):
        # FIXME check if freelists and committed backend collides.
        free_lists = set([(freeblock_addr, size) for freeblock_addr,size in self._validator.HEAP_get_freelists(self._heap)])
        freesize = sum([c[1] for c in free_lists])
        log.debug('+ freeLists: nb_free_chunk:0x%0.4x total_size:0x%0.5x', len(free_lists), freesize)
        return free_lists
