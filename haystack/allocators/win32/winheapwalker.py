# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

from __future__ import print_function
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
        log.debug('+ Heap @%0.8x size: %d # %s',self._heap_mapping.start, len(self._heap_mapping), self._heap_mapping)
        # real allocations from the process pov
        self._user_allocs = None
        self._user_free_chunks = None
        # allocation from the heap backend pov (backend_committed+vallocs)
        self._backend_allocs = None
        # heap backend allocations
        self._backend_committed = None
        self._backend_free = None
        # heap frontend allocation
        self._fth_committed = None
        self._fth_free = None
        # virtual allocation
        self._valloc_committed = None
        #
        self._validator = self._create_validator()
        return

    def _create_validator(self):
        """ return the validator """
        raise NotImplementedError('Please implement all methods')

    def get_heap(self):
        """ return the ctypes heap struct mapped at address on the mapping"""
        # no cache, no segfault.
        return self._heap_mapping.read_struct(self._address, self._heap_module.HEAP)

    def get_heap_validator(self):
        return self._validator

    def __contains__(self, address):
        """ Does the heap walker or its relevant segments contains this address"""
        raise NotImplementedError('Please implement all methods')

    def get_backend_allocations(self):
        """
        returns all backend allocations
        """
        if self._backend_allocs is None:
            self._set_chunk_lists()
        return self._backend_allocs

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) and only the user writeable part.
        addr and size EXCLUDES the HEAP_ENTRY header.
        """
        if self._user_allocs is None:
            self._set_chunk_lists()
        return self._user_allocs

    def get_user_free_chunks(self):
        """ returns all free chunks that are not allocated (addr,size) .
                addr and size EXCLUDES the HEAP_ENTRY header.
        """
        if self._user_free_chunks is None:
            self._set_chunk_lists()
        return self._user_free_chunks

    def get_backend_free_chunks(self):
        """
        """
        if self._backend_free is None:
            self._set_chunk_lists()
        return self._backend_free

    def get_frontend_free_chunks(self):
        """
        """
        if self._fth_free is None:
            self._set_chunk_lists()
        return self._fth_free

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
        chunks, backend_free_chunks = self._get_chunks()
        self._check_sizes(chunks)
        self._check_sizes(backend_free_chunks)

        # chunk == self._backend_committed
        self._backend_allocs = vallocs | chunks
        self._check_sizes(self._backend_allocs)

        # free_lists == free_chunks.
        # either get the _get_free_lists() or use free_chunks. Its the same.
        if False:
            log.warning('Duplicate walking of free chunks')
            free_lists = self._get_freelists()
            # need to cut sizeof(HEAP_ENTRY) from address and size
            # FIXME ? why report calculation up to here ?
            sublen = ctypes.sizeof(self._heap_module.HEAP_ENTRY)
            backend_free_chunks = set([(addr + sublen, size - sublen) for addr, size in free_lists])
            if len(backend_free_chunks) != len(free_lists):
                log.warning('Weird: len(free_chunks) != len(free_lists)')
            self._check_sizes(backend_free_chunks)

        # adjust the user allocations based on if there is a frontend or not
        if self.get_heap().FrontEndHeapType == 0:
            self._user_allocs = self._backend_allocs
            self._user_free_chunks = backend_free_chunks
        else:
            front_allocs, front_free_chunks = self._get_frontend_chunks()
            self._check_sizes(front_allocs)
            self._check_sizes(front_free_chunks)
            # point to header
            #front_allocs2 = set([(addr + sublen, size - sublen) for addr, size in front_allocs])
            #front_free_chunks2 = set([(addr + sublen, size - sublen) for addr, size in front_free_chunks])
            # points to chunk
            front_allocs2 = set([(addr, size) for addr, size in front_allocs])
            front_free_chunks2 = set([(addr, size) for addr, size in front_free_chunks])
            self._check_sizes(front_allocs2)
            self._check_sizes(front_free_chunks2)

            # print "backend_allocs", hex(sum([s for a, s in self._backend_allocs]))
            # print "frontend_allocs", hex(sum([s for a, s in front_allocs2]))
            # print "backend_free_chunks", hex(sum([s for a, s in backend_free_chunks]))
            # print "frontend_free_chunks", hex(sum([s for a, s in front_free_chunks2]))
            # import code
            # code.interact(local=locals())

            if self.get_heap().FrontEndHeapType == 1:
                # LAL: reports vallocs and (_get_chunks-lal) as committed
                #      reports lal | free_list as free
                # TODO + overhead
                # FIXME , use same code than LFH ?
                self._user_allocs = self._backend_allocs - front_free_chunks2
                self._user_free_chunks = front_free_chunks2 | backend_free_chunks
            elif self.get_heap().FrontEndHeapType == 2:
                # free chunks are backend free chunks + frontend free chunks
                self._user_free_chunks = backend_free_chunks | front_free_chunks2
                # we only keep backend allocations that are not used by LFH
                backend_allocs2 = set()
                for start, size in self._backend_allocs:
                    end = start + size
                    lfh_block = False
                    for front_addr, front_addr_size in front_allocs2:
                        if start <= front_addr < end:
                            lfh_block = True
                            break
                    if not lfh_block:
                        backend_allocs2.add((start, size))
                self._user_allocs = backend_allocs2 | front_allocs2

        return

    def _check_sizes(self, chunks):
        for addr, size in chunks:
            if size <= 0:
                print(self._heap_mapping)
                raise ValueError("chunk size cannot be negative: 0x%x %d" % (addr,size))

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
            #self._backend_committed, self._backend_free = self.get_heap_validator().get_backend_chunks(self.get_heap())
            _backend_committed, _backend_free = self.get_heap_validator().get_backend_chunks(self.get_heap())
            # HEAP_ENTRY.Size is in chunk size. (8 bytes / 16 bytes )
            sublen = ctypes.sizeof(self._heap_module.HEAP_ENTRY)
            # get the proper offset and sizes
            self._backend_committed = set([(addr + sublen, size - sublen) for addr, size in _backend_committed])
            self._backend_free = set([(addr + sublen, size - sublen) for addr, size in _backend_free])
            # allocsize = sum([c[1] for c in self._backend_committed])
            # freesize = sum([c[1] for c in self._backend_free])
            # log.debug('\t+ Segment Chunks: alloc: %0.4d [%0.5d B] free: %0.4d [%0.5d B]' % (
            #    len(self._backend_committed), allocsize, len(self._backend_free), freesize))
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

    def list_used_mappings(self):
        """
        A Windows heap is composed of segments
        Segment cover multiple mappings, with UCR being gaps between mappings.
        We return the list of mappings in this memory_handler that are used by this heap
        :return:
        """
        boundaries = []
        for segment in self._validator.get_segment_list(self.get_heap()):
            start = segment._orig_address_
            end = self._target.get_target_ctypes_utils().get_pointee_address(segment.LastValidEntry)
            boundaries.append((start, end))
        # look at all mappings
        used = []
        for m in self._memory_handler.get_mappings():
            for start, end in boundaries:
                if m.start <= start < m.end:
                    # corner case. Segment.start is at an offset
                    used.append(m)
                    break
                elif start <= m.start < end:
                    used.append(m)
                    break
        return used


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
            map_start = mapping.start
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
                    elif self.__is_kernel_heap(mapping, addr, bits):
                        _heap_offset = addr - map_start
                        heap_addr = mapping.start + _heap_offset
                        return self._walker_type()(self._memory_handler,
                                              self._cpu[bits]['target'],
                                              self._cpu[bits]['module'],
                                              mapping,
                                              self._cpu[bits]['constraints'],
                                              heap_addr)
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
        validator = self._validator_type()(self._memory_handler, constraints, target_platform, heap_module)
        load = validator.load_members(heap, 3)
        log.debug('HeapFinder._is_heap %s %s', mapping, load)
        return load

    def __is_kernel_heap(self, mapping, address, bits):
        """
        test if a mapping is a heap in KERNEL space, from a USER space address memory dump
        :param mapping: IMemoryMapping
        :return:
        """
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        offset = self._cpu[bits]['signature_offset']
        # switch to the right target
        heap_module = self._cpu[bits]['module']
        target_platform = self._cpu[bits]['target']
        constraints = self._cpu[bits]['constraints']
        heap = mapping.read_struct(address, heap_module.HEAP)
        # TEST Kernel address space.
        # winxp has heap.UnusedUnCommittedRanges
        # win 7 has heap.BaseAddress
        kernel_ptr = self._get_heap_possible_kernel_pointer_from_heap(target_platform, heap)
        if not self.__is_kernel_address_space(bits, kernel_ptr):
            return False
        # Else we found a kernel AS HEAP
        old_start = mapping.start
        # start = kernel_ptr & 0xFFFFFFFFFFFF0000
        start = kernel_ptr & ((1 << bits) - 0x10000)
        self._memory_handler.rebase_mapping(mapping, start)
        heap = mapping.read_struct(start, heap_module.HEAP)
        # validator is (should be) then target-bound
        validator = self._validator_type()(self._memory_handler, constraints, target_platform, heap_module)
        load = validator.load_members(heap, 3)
        log.debug('HeapFinder._is_heap %s %s', mapping, load)
        if not load:
            self._memory_handler.rebase_mapping(mapping, old_start)
        else:
            log.debug('[!] KERNEL SPACE HEAP FOUND ! USER:0x%x => KERNEL:0x%x', address, start)
        return load

    def _get_heap_possible_kernel_pointer_from_heap(self, target_platform, heap):
        raise NotImplementedError

    def __is_kernel_address_space(self, bits, address):
        # Session space is return 0xFFFFF90000000000 <= address <= 0xFFFFF97FFFFFFFFF
        start, end = self._cpu[bits]['kernel_as']
        # return 0xFFFF080000000000 <= address <= 0xFFFFFFFFFFFFFFFF
        return start <= address <= end

    def search_heap_direct(self, start_address_mapping):
        """
        return a ctypes heap struct mapped at address on the mapping
        Will use the memory handler
        """
        heap = self._memory_handler.get_mapping_for_address(start_address_mapping)
        if not heap:
            raise ValueError("Address not found")
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

    def list_heap_walkers(self):
        """
        return the list of heaps that load as heaps
        Take into account the fact that Segment and mappings exists
        """
        if not self._heap_walkers:
            self._heap_walkers = []
            self._heap_walkers_dict = dict()
            for mapping in self._memory_handler:
                # walker could be a kernel AS heap, rebased.
                # Double check we have looked at it already.
                if mapping.start in self._heap_walkers_dict:
                    continue
                walker = self._find_heap(mapping)
                if walker:
                    self._heap_walkers.append(walker)
                    self._heap_walkers_dict[mapping.start] = walker
                    self._heap_walkers_dict[walker.get_heap_address()] = walker
            # sort the list
            self._heap_walkers.sort(key=lambda walker: walker.get_heap_address())
            # now look at segment & all used mappings.
            for walker in self._heap_walkers:
                # for all 'child' mapping used by a segment of thisHEAP
                for m in walker.list_used_mappings():
                    if m.start not in self._heap_walkers_dict:
                        # point this mapping to the Root Heap walker
                        self._heap_walkers_dict[m.start] = walker
                pass
        return self._heap_walkers
