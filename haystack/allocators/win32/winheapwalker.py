# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import ctypes
import logging
import struct

from haystack.abc import interfaces
from haystack.allocators import heapwalker
from haystack.search import searcher

log = logging.getLogger('winheapwalker')


class WinHeapWalker(heapwalker.HeapWalker):
    """
    Helpers functions that return pure python lists - no ctypes in here.

    Backend allocation in BlocksIndex
    FTH allocation in Heap.LocalData[n].SegmentInfo.CachedItems
    Virtual allocation
    """

    def _init_heap(self):
        self._heap = self._heap_mapping.read_struct(self._address, self._heap_module.HEAP)
        log.debug('+ Heap @%0.8x size: %d # %s',self._heap_mapping.start, len(self._heap_mapping), self._heap_mapping)
        # placeholders
        self._allocs = None
        self._free_chunks = None
        self._backend_committed = None
        self._backend_free = None
        self._fth_committed = None
        self._fth_free = None
        self._valloc_committed = None
        self._valloc_free = None
        #
        self._validator = self._create_validator()
        return

    def _create_validator(self):
        """ return the validator """
        raise NotImplementedError('Please implement all methods')

    def get_heap(self):
        """ return the ctypes heap struct mapped at address on the mapping"""
        return self._heap

    def get_heap_validator(self):
        return self._validator

    def __contains__(self, address):
        """ Does the heap walker or its relevant segments contains this address"""
        raise NotImplementedError('Please implement all methods')


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
        self._check_sizes(vallocs)
        chunks, free_chunks = self._get_chunks()
        self._check_sizes(chunks)
        self._check_sizes(free_chunks)
        # need to cut sizeof(HEAP_ENTRY) from address and size
        # FIXME ? why report calculation up to here ?
        sublen = ctypes.sizeof(self._heap_module.HEAP_ENTRY)
        # make the user allocated list
        # lst = vallocs | chunks
        chunks2 = set([(addr + sublen, size - sublen) for addr, size in chunks])
        # chunks2 = set([(addr, size) for addr, size in chunks])
        backend_allocs = vallocs | chunks2

        # FIXME, we have a 0 size chunks.
        self._check_sizes(backend_allocs)

        # free_lists == free_chunks.
        if False:
            log.warning('Duplicate walking of free chunks')
            free_lists = self._get_freelists()
            backend_free_chunks = set([(addr + sublen, size - sublen) for addr, size in free_lists])
            if len(free_chunks) != len(free_lists):
                log.warning('Weird: len(free_chunks) != len(free_lists)')
        else:
            backend_free_chunks = set([(addr + sublen, size - sublen) for addr, size in free_chunks])
        self._check_sizes(backend_free_chunks)

        # frontend too
        if self.get_heap().FrontEndHeapType == 0:
            self._allocs = backend_allocs
            self._free_chunks = backend_free_chunks
        else:
            front_allocs, front_free_chunks = self._get_frontend_chunks()
            self._check_sizes(front_allocs)
            self._check_sizes(front_free_chunks)
            # point to header
            #front_allocs2 = set([(addr + sublen, size - sublen) for addr, size in front_allocs])
            #front_free_chunks2 = set([(addr + sublen, size - sublen) for addr, size in front_free_chunks])
            # points to chunk
            front_allocs2 = set([(addr, size ) for addr, size in front_allocs])
            front_free_chunks2 = set([(addr, size) for addr, size in front_free_chunks])
            self._check_sizes(front_allocs2)
            self._check_sizes(front_free_chunks2)

            if self.get_heap().FrontEndHeapType == 1:
                # LAL: reports vallocs and (_get_chunks-lal) as committed
                #      reports lal | free_list as free
                # TODO + overhead
                self._allocs = backend_allocs - front_free_chunks2
                self._free_chunks = front_free_chunks2 | backend_free_chunks
            elif self.get_heap().FrontEndHeapType == 2:
                # LFH: reports vallocs and (_get_chunks-lfh_free | lfh_committed) as committed
                #      reports lfh_free | free_list as free
                self._allocs = backend_allocs - front_free_chunks2 | front_allocs2
                self._free_chunks = front_free_chunks2 | backend_free_chunks

        return

    def _check_sizes(self, chunks):
        for addr, size in chunks:
            if size <= 0:
                print self._heap_mapping
                raise ValueError("chunk size cannot be negative: 0x%x %d" % (addr,size))

    def get_heap_children_mmaps(self):
        """ use backend heap chunks to establish the hierarchy between segment and mappings"""
        if self._child_heaps is None:
            child_heaps = set()
            # check addresses of free chunks
            for _addr, s in self.get_free_chunks():
                m = self._memory_handler.get_mapping_for_address(_addr)
                if (m != self._heap_mapping) and (m not in child_heaps):
                    child_heaps.add(m)
                    pass
            # and of allocated / vallocs
            for _addr, s in self.get_user_allocations():
                m = self._memory_handler.get_mapping_for_address(_addr)
                if (m != self._heap_mapping) and (m not in child_heaps):
                    child_heaps.add(m)
                    pass
            self._child_heaps = list(child_heaps)
        self._child_heaps.sort()
        log.debug('get_heap_children_mmaps b')
        return self._child_heaps

    def _get_virtualallocations(self):
        """ returns addr,size of committed,free vallocs heap entries"""
        if self._valloc_committed is None:
            allocs = self.get_heap_validator().HEAP_get_virtual_allocated_blocks_list(self.get_heap())
            self._valloc_committed = set([(addr, c_size) for addr, c_size, r_size in allocs])
            log.debug('\t+ %d vallocated blocks' % len(self._valloc_committed))
        return self._valloc_committed

    def _get_chunks(self):
        """ returns addr,size of committed,free heap entries in blocksindex"""
        if (self._backend_committed, self._backend_free) == (None, None):
            self._backend_committed, self._backend_free = self.get_heap_validator().get_backend_chunks(self.get_heap())
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
            self._fth_committed, self._fth_free = self.get_heap_validator().get_frontend_chunks(self.get_heap())
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
        free_lists = set([(freeblock_addr, size) for freeblock_addr,size in self.get_heap_validator().HEAP_get_freelists(self.get_heap())])
        freesize = sum([c[1] for c in free_lists])
        log.debug('+ freeLists: nb_free_chunk:0x%0.4x total_size:0x%0.5x', len(free_lists), freesize)
        return free_lists


class WinHeapFinder(heapwalker.HeapFinder):

    def __init__(self, memory_handler):
        """
        :param memory_handler: IMemoryHandler
        :return: HeapFinder
        """
        super(WinHeapFinder, self).__init__(memory_handler)
        self._cpu = self._make_dual_arch_ctypes()
        return

    def _validator_type(self):
        """ return the validator class type"""
        raise NotImplementedError('Please implement all methods')

    def _walker_type(self):
        """ return the heap walker class type"""
        raise NotImplementedError('Please implement all methods')

    def _make_dual_arch_ctypes(self):
        """ return the dual arch reference ctypes """
        raise NotImplementedError('Please implement all methods')

    def _find_heap(self, mapping):
        """
        return a ctypes heap struct mapped at address on the mapping.
        Funny enough, a X64 process could have 32 bits and 64 bits heaps.
        """
        for addr in range(mapping.start, mapping.end, 0x1000):
            # offset of Signature in 32 and 64 bits
            for bits in [32, 64]:
                offset = self._cpu[bits]['signature_offset']
                signature = struct.unpack('I', mapping.read_bytes(addr+offset, 4))[0]
                # WinHeap value for HEAP.Signature
                if signature == 0xeeffeeff:
                    # deep load and check the heap with constraint validation
                    if self.__is_heap(mapping, addr, bits):
                        return self._walker_type()(self._memory_handler,
                                              self._cpu[bits]['target'],
                                              self._cpu[bits]['module'],
                                              mapping,
                                              self._cpu[bits]['constraints'],
                                              addr)
                    # otherwise try another combination
        return None

    def __is_heap(self, mapping, address, bits):
        """
        test if a mapping is a heap
        :param mapping: IMemoryMapping
        :return:
        """
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        # switch to the right target
        heap_module = self._cpu[bits]['module']
        target_platform = self._cpu[bits]['target']
        constraints = self._cpu[bits]['constraints']
        heap = mapping.read_struct(address, heap_module.HEAP)
        # validator is (should be) then target-bound
        validator = self._validator_type()(self._memory_handler,
                                                constraints,
                                                target_platform,
                                                heap_module)
        load = validator.load_members(heap, 1)
        log.debug('HeapFinder._is_heap %s %s', mapping, load)
        return load

    def search_heap_direct(self, start_address_mapping):
        """
        return a ctypes heap struct mapped at address on the mapping
        Will use the memory handler
        """
        heap = self._memory_handler.get_mapping_for_address(start_address_mapping)
        bits = self._memory_handler.get_target_platform().get_cpu_bits()
        heap_module = self._cpu[bits]['module']
        constraints = self._cpu[bits]['constraints']
        my_searcher = searcher.AnyOffsetRecordSearcher(self._memory_handler,
                                                       constraints,
                                                       [heap])
        # on ly return first results in each mapping
        log.debug("_search_heap_direct in %s", start_address_mapping)
        results = my_searcher._load_at(heap, start_address_mapping, heap_module.HEAP, depth=5)
        return results
