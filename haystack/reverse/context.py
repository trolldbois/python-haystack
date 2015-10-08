#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import pickle
# import dill as pickle

import numpy
import os

from haystack import dump_loader
from haystack.reverse import utils
from haystack.reverse import config
from haystack.reverse import structure
from haystack.reverse import searchers
from haystack.reverse import matchers
from haystack.reverse import enumerators

"""
This is a controller to parse allocated chunk from memory and
 guess/reverse the record and its field member types.
"""


log = logging.getLogger('context')


class ReverserContext(object):
    """
    TODO: Change Name to MmapReverserContext
    add methods for chained mmap
    Add check for context, only on valid heaps ( getHeaps)
    """

    def __init__(self, memory_handler, heap):
        self.memory_handler = memory_handler
        # cache it
        memory_handler.cache_context_for_heap(heap, self)
        self.dumpname = memory_handler.get_name()
        self.heap = heap
        self._heap_start = heap.start
        self._word_size = self.memory_handler.get_target_platform().get_word_size()
        self.parsed = set()
        self._function_names = dict()
        # refresh heap pointers list and allocators chunks
        self._init2()
        return

    def _init2(self):
        # force reload JIT
        self._reversedTypes = dict()
        self._structures = None

        if not os.access(config.get_cache_folder_name(self.dumpname), os.F_OK):
            os.mkdir(config.get_cache_folder_name(self.dumpname))

        finder = self.memory_handler.get_heap_finder()
        heap_walker = finder.get_heap_walker(self.heap)

        log.info('[+] Searching pointers in heap')
        # get all pointers found in from allocated space.
        all_offsets, all_values = self.get_heap_pointers_from_allocated(heap_walker)
        self._pointers_values = all_values
        self._pointers_offsets = all_offsets

        log.info('[+] Gathering allocated heap chunks')
        res = utils.cache_get_user_allocations(self, heap_walker)
        self._structures_addresses, self._structures_sizes = res

        # clean a bit the open fd's
        self.memory_handler.reset_mappings()

        #if self.memory_handler.get_target_platform().get_os_name() not in ['winxp', 'win7']:
        #    log.info('[+] Reversing function pointers names')
        #    # TODO INLINE CACHED
        #    # dict(libdl.reverseLocalFonctionPointerNames(self) )
        #    self._function_names = dict()
        return

    def get_structure_for_address(self, addr):
        """
        return the structure.AnonymousStructInstance associated with this address

        :param addr:
        :return:
        """
        return self._get_structures()[addr]

    # TODO implement a LRU cache
    def _get_structures(self):
        if self._structures is not None and len(
                self._structures) == len(self._structures_addresses):
            return self._structures
        # otherwise cache Load
        log.info('[+] Loading cached structures list')
        self._structures = dict(
            [(long(vaddr), s) for vaddr, s in structure.cacheLoadAllLazy(self)])
        log.info('[+] Loaded %d cached structures addresses from disk', len(self._structures))

        # If we are missing some structures from the cache loading
        # then recreated them in cache from Allocated memory
        nb_missing = len(self._structures_addresses) - len(self._structures)
        if nb_missing != 0:
            import reversers

            log.info('[+] Missing cached structures %d' % nb_missing)
            if nb_missing < 10:
                log.warning('TO check missing:%d unique: %d', nb_missing, len(set(self._structures_addresses) - set(self._structures)))
            # use BasicCachingReverser to get user blocks
            cache_reverse = reversers.BasicCachingReverser(self)
            _ = cache_reverse.reverse(self)
            # mallocRev.check_inuse(self)
            log.info('[+] Built %d/%d structures from allocations',
                     len(self._structures),
                     len(self._structures_addresses))
        return self._structures

    def getStructureSizeForAddr(self, addr):
        ''' return the structure.AnonymousStructInstance associated with this addr'''
        itemindex = numpy.where(
            self._structures_addresses == numpy.int64(addr))[0][0]
        return self._structures_sizes[itemindex]

    def structuresCount(self):
        if self._structures is not None and len(
                self._structures) == len(self._structures_addresses):
            return len(self._get_structures())
        return len(self._structures_addresses)

    def getStructureAddrForOffset(self, offset):
        '''Returns the closest containing structure address for this offset in this heap.'''
        # if offset not in self.heap:
        #  raise ValueError('address 0x%0.8x not in heap 0x%0.8x'%(offset, self.heap.start))
        return utils.closestFloorValue(
            offset, self._structures_addresses)[0]  # [1] is the index of [0]

    def getStructureForOffset(self, ptr_value):
        '''Returns the structure containing this address'''
        st = self.get_structure_for_address(
            self.getStructureAddrForOffset(ptr_value))
        if st._vaddr <= ptr_value < (st._vaddr + len(st)):
            return st
        raise IndexError('No known structure covers that ptr_value')

    def listOffsetsForPointerValue(self, ptr_value):
        '''Returns the list of offsets where this value has been found'''
        return [int(self._pointers_offsets[offset])
                for offset in numpy.where(self._pointers_values == ptr_value)[0]]

    def listPointerValueInHeap(self):
        '''Returns the list of pointers found in the heap'''
        return map(long, self._pointers_values)

    def listStructuresAddrForPointerValue(self, ptr_value):
        '''Returns the list of structures addresses with a member with this pointer value '''
        return sorted(set([int(self.getStructureAddrForOffset(offset))
                           for offset in self.listOffsetsForPointerValue(ptr_value)]))

    def listStructuresForPointerValue(self, ptr_value):
        '''Returns the list of structures with a member with this pointer value '''
        return [self._get_structures()[addr]
                for addr in self.listStructuresAddrForPointerValue(ptr_value)]

    def list_allocations_addresses(self):
        return map(long, self._structures_addresses)

    def list_allocations_sizes(self):
        return map(long, self._structures_sizes)

    def listStructuresAddresses(self):
        return map(long, self._get_structures().keys())

    def listStructures(self):
        return self._get_structures().values()

    def getReversedType(self, typename):
        if typename in self._reversedTypes:
            return self._reversedTypes[typename]
        return None

    def addReversedType(self, typename, t):
        self._reversedTypes[typename] = t

    def listReversedTypes(self):
        return self._reversedTypes.values()

    # name of cache files
    def get_filename_cache_context(self):
        return config.get_cache_filename(config.CACHE_CONTEXT, self.dumpname, self._heap_start)

    def get_filename_cache_headers(self):
        return config.get_cache_filename(config.CACHE_GENERATED_PY_HEADERS_VALUES, self.dumpname, self._heap_start)

    def get_filename_cache_graph(self):
        return config.get_cache_filename(config.CACHE_GRAPH, self.dumpname, self._heap_start)

    def get_folder_cache_structures(self):
        return config.get_record_cache_folder_name(self.dumpname)

    def get_filename_cache_pointers_addresses(self):
        return config.get_cache_filename(config.CACHE_HEAP_ADDRS, self.dumpname, self._heap_start)

    def get_filename_cache_pointers_values(self):
        return config.get_cache_filename(config.CACHE_HEAP_VALUES, self.dumpname, self._heap_start)

    def get_filename_cache_allocations_addresses(self):
        return config.get_cache_filename(config.CACHE_MALLOC_CHUNKS_ADDRS, self.dumpname, self._heap_start)

    def get_filename_cache_allocations_sizes(self):
        return config.get_cache_filename(config.CACHE_MALLOC_CHUNKS_SIZES, self.dumpname, self._heap_start)

    def get_heap_pointers(self):
        """
        UNUSED

        Search Heap pointers values in stack and heap.
            records values and pointers address in heap.
        :param memory_handler:
        :param heap_walker:
        :return:
        """
        feedback = searchers.NoFeedback()
        matcher = matchers.PointerEnumerator(self.memory_handler)
        enumerator = enumerators.WordAlignedEnumerator(self.heap, matcher, feedback, self._word_size)
        return utils._get_cache_heap_pointers(self, enumerator)

    def get_heap_pointers_from_allocated(self, heap_walker):
        """
        Search Heap pointers values in stack and heap.
            records values and pointers address in heap.
        :param dumpfilename:
        :param memory_handler:
        :param heap_walker:
        :return:
        """
        feedback = searchers.NoFeedback()
        matcher = matchers.PointerEnumerator(self.memory_handler)
        enumerator = enumerators.AllocatedWordAlignedEnumerator(heap_walker, matcher, feedback, self._word_size)
        return utils._get_cache_heap_pointers(self, enumerator)

    @classmethod
    def cacheLoad(cls, memory_handler, heap_addr):
        dumpname = os.path.normpath(memory_handler.get_name())
        config.create_cache_folder_name(dumpname)
        context_cache = config.get_cache_filename(config.CACHE_CONTEXT, dumpname, heap_addr)
        try:
            with file(context_cache, 'r') as fin:
                ctx = pickle.load(fin)
        except EOFError as e:
            os.remove(context_cache)
            log.error(
                'Error in the context file. File cleaned. Please restart.')
            raise RuntimeError('Error in the context file. File cleaned. Please restart.')
        log.debug('\t[-] loaded my context from cache')
        ctx.config = config
        ctx.memory_handler = memory_handler
        ctx.heap = ctx.memory_handler.get_mapping_for_address(ctx._heap_start)
        # cache it
        memory_handler.cache_context_for_heap(ctx.heap, ctx)

        ctx._init2()
        return ctx

    def save(self):
        # we only need dumpfilename to reload _memory_handler, addresses to reload
        # cached structures
        cache_context_filename = self.get_filename_cache_context()
        try:
            with file(cache_context_filename, 'w') as fout:
                pickle.dump(self, fout)
        except pickle.PicklingError, e:
            log.error("Pickling error on %s, file removed", cache_context_filename)
            os.remove(cache_context_filename)
            raise e

    def reset(self):
        self.memory_handler.reset_mappings()
        try:
            cache_context_filename = self.get_filename_cache_context()
            os.remove(cache_context_filename)
        except OSError as e:
            pass
        try:
            if not os.access(config.CACHE_STRUCT_DIR, os.F_OK):
                return
            record_cache_folder = self.get_folder_cache_structures()
            for r, d, files in os.walk(record_cache_folder):
                for f in files:
                    os.remove(os.path.join(r, f))
                os.rmdir(r)
        except OSError as e:
            pass

    def __getstate__(self):
        """The important things to pickle are:
               dumpname
               parsed
               _heap_start
           Ignore the rest
        """
        # FIXME, double check and delete
        #d = self.__dict__.copy()
        #del d['_memory_handler']
        #del d['heap']
        #del d['_structures']
        #del d['_structures_addresses']
        ##del d['_pointers_values']
        ##del d['_pointers_offsets']
        #del d['_malloc_addresses']
        #del d['_malloc_sizes']
        d = dict()
        d['dumpname'] = self.__dict__['dumpname']
        d['parsed'] = self.__dict__['parsed']
        d['_heap_start'] = self.__dict__['_heap_start']
        d['_word_size'] = self.__dict__['_word_size']
        return d

    def __setstate__(self, d):
        self.dumpname = d['dumpname']
        self.parsed = d['parsed']
        self._heap_start = d['_heap_start']
        self._word_size = d['_word_size']
        self._structures = None
        self._function_names = dict()
        return


# FIXME - get context should be on memory_handler.
#@deprecated
def get_context(fname, heap_addr):
    """
    Load a dump file, and create a reverser context object.
    @return context: a ReverserContext
    """
    memory_handler = dump_loader.load(fname)
    try:
        ctx = ReverserContext.cacheLoad(memory_handler, heap_addr)
    except IOError as e:
        finder = memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()
        heap = memory_handler.get_mapping_for_address(heap_addr)
        ctx = ReverserContext(memory_handler, heap)
    return ctx



def get_context_for_address(memory_handler, address):
    """
    Returns the haystack.reverse.context.ReverserContext of the process
    for the HEAP that hosts this address
    """
    assert isinstance(address, long) or isinstance(address, int)
    mmap = memory_handler.get_mapping_for_address(address)
    if not mmap:
        raise ValueError("Invalid address: 0x%x", address)
    finder = memory_handler.get_heap_finder()
    if mmap not in finder.get_heap_mappings():
        # addr is not a heap addr,
        found = False
        # or its in a child heap (win7)
        for h in finder.get_heap_mappings():
            # FIXME : use a get_children or something
            # winHeapwalker.get_heap_children_mmaps
            if hasattr(h, '_children'):
                if mmap in h._children:
                    found = True
                    mmap = h
                    break
        if not found:
            raise ValueError("Address is not in heap: 0x%x", address)
    cached = memory_handler.get_cached_context_for_heap(mmap)
    if cached is not None:
        return cached
    # found
    heap_addr = mmap.get_marked_heap_address()
    try:
        ctx = ReverserContext.cacheLoad(memory_handler, heap_addr)
    except IOError as e:
        ctx = ReverserContext(memory_handler, mmap)
    return ctx

if __name__ == '__main__':
    pass
