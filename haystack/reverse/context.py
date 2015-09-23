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
from haystack.reverse import structure, reversers

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
        self.dumpname = memory_handler.get_name()
        self.heap = heap
        self._heap_start = heap.start
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

        log.info('[+] Fetching cached structures addresses list')
        #ptr_values, ptr_offsets, aligned_ptr, not_aligned_ptr = utils.getHeapPointers(self.dumpname, self._memory_handler)

        # FIXME: no use I think
        heap_offsets, heap_values = utils.getHeapPointers(self.dumpname, self.memory_handler)
        self._pointers_values_heap = heap_values
        self._pointers_offsets_heap = heap_offsets

        # test with all mmap in target
        all_offsets, all_values = utils.getAllPointers(self.dumpname, self.memory_handler)
        self._pointers_values = all_values
        self._pointers_offsets = all_offsets

        if self.memory_handler.get_target_platform().get_os_name() not in ['winxp', 'win7']:
            log.info('[+] Reversing function pointers names')
            # TODO INLINE CACHED
            # dict(libdl.reverseLocalFonctionPointerNames(self) )
            self._function_names = dict()

        log.info('[+] Fetching cached malloc chunks list')
        # malloc_size is the structures_sizes,
        # TODO adaptable allocator win32/linux
        self._malloc_addresses, self._malloc_sizes = utils.getAllocations(
            self.dumpname, self.memory_handler, self.heap)
        self._structures_addresses = self._malloc_addresses
        self._user_alloc_addresses = self._malloc_addresses
        self._user_alloc_sizes = self._malloc_sizes
        # clean a bit
        self.memory_handler.reset_mappings()

        return

    def has_allocations(self):
        ''' allocation based mmap '''
        return True

    def getStructureForAddr(self, addr):
        ''' return the structure.AnonymousStructInstance associated with this addr'''
        return self._get_structures()[addr]

    ''' TODO implement a LRU cache '''

    def _get_structures(self):
        # TODO use HeapWalker ... win32 + libc
        if self._structures is not None and len(
                self._structures) == len(self._malloc_addresses):
            return self._structures
        # cache Load
        log.info('[+] Fetching cached structures list')
        self._structures = dict(
            [(long(vaddr), s) for vaddr, s in structure.cacheLoadAllLazy(self)])
        log.info('[+] Fetched %d cached structures addresses from disk', len(self._structures))

        # no all structures yet, make them from Allocated memory
        if len(self._structures) != len(self._malloc_addresses):
            log.info('[+] No cached structures - making them from allocated memory reversers %d|%d' %
                     (len(self._structures), len(self._malloc_addresses)))
            if (len(self._malloc_addresses) - len(self._structures)) < 10:
                log.warning('close numbers to check %s' %
                            (set(self._malloc_addresses) -
                             set(self._structures)))
                self.parsed = set()
            # use GenericHeapAllocationReverser to get user blocks
            mallocRev = reversers.GenericHeapAllocationReverser(self)
            context = mallocRev.reverse(self)
            # mallocRev.check_inuse(self)
            log.info(
                '[+] Built %d/%d structures from malloc blocs' %
                (len(
                    self._structures), len(
                    self._malloc_addresses)))

        return self._structures

    def getStructureSizeForAddr(self, addr):
        ''' return the structure.AnonymousStructInstance associated with this addr'''
        itemindex = numpy.where(
            self._malloc_addresses == numpy.int64(addr))[0][0]
        return self._malloc_sizes[itemindex]

    def structuresCount(self):
        if self._structures is not None and len(
                self._structures) == len(self._malloc_addresses):
            return len(self._get_structures())
        return len(self._malloc_addresses)

    def getStructureAddrForOffset(self, offset):
        '''Returns the closest containing structure address for this offset in this heap.'''
        # if offset not in self.heap:
        #  raise ValueError('address 0x%0.8x not in heap 0x%0.8x'%(offset, self.heap.start))
        return utils.closestFloorValue(
            offset, self._structures_addresses)[0]  # [1] is the index of [0]

    def getStructureForOffset(self, ptr_value):
        '''Returns the structure containing this address'''
        st = self.getStructureForAddr(
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

    @classmethod
    def cacheLoad(cls, memory_handler):#, cache_folder_name):
        dumpname = os.path.normpath(memory_handler.get_name())
        config.create_cache_folder_name(dumpname)
        context_cache = config.get_cache_filename(config.CACHE_CONTEXT, dumpname)
        try:
            with file(context_cache, 'r') as fin:
                context = pickle.load(fin)
        except EOFError as e:
            os.remove(context_cache)
            log.error(
                'Error in the context file. File cleaned. Please restart.')
            raise RuntimeError('Error in the context file. File cleaned. Please restart.')
        log.debug('\t[-] loaded my context from cache')
        context.config = config
        context.memory_handler = memory_handler
        context.heap = context.memory_handler.get_mapping_for_address(
            context._heap_start)

        context._init2()
        return context

    def save(self):
        # we only need dumpfilename to reload _memory_handler, addresses to reload
        # cached structures
        context_cache = config.get_cache_filename(
            config.CACHE_CONTEXT,
            self.dumpname)
        try:
            with file(context_cache, 'w') as fout:
                pickle.dump(self, fout)
        except pickle.PicklingError, e:
            log.error("Pickling error on %s, file removed",context_cache)
            os.remove(context_cache)
            raise e

    def reset(self):
        self.memory_handler.reset_mappings()
        try:
            os.remove(
                config.get_cache_filename(
                    config.CACHE_CONTEXT,
                    self.dumpname))
        except OSError as e:
            pass
        try:
            if not os.access(config.CACHE_STRUCT_DIR, os.F_OK):
                return
            for r, d, files in os.walk(
                    config.get_cache_filename(config.CACHE_STRUCT_DIR, self.dumpname)):
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
        return d

    def __setstate__(self, d):
        self.dumpname = d['dumpname']
        self.parsed = d['parsed']
        self._heap_start = d['_heap_start']
        self._structures = None
        self._function_names = dict()
        return


def get_context(fname):
    """
    Load a dump file, and create a reverser context object.
    @return context: a ReverserContext
    """
    memory_handler = dump_loader.load(fname)
    try:
        context = ReverserContext.cacheLoad(memory_handler)#, memory_handler.get_name())
    except IOError as e:
        finder = memory_handler.get_heap_finder()
        context = ReverserContext(memory_handler, finder.get_heap_mappings()[0])#, memory_handler.get_name())
    # cache it
    # FIXME that needs to go away
    context.heap._context = context
    return context

# FIXME s/memory_handler.get_context(/get_context_for_addr(memoryhandler, /g
# move to a IContextHandler
def get_context_for_address(memory_handler, addr):
    """Returns the haystack.reverse.context.ReverserContext of this dump.
    """
    assert isinstance(addr, long) or isinstance(addr, int)
    mmap = memory_handler.get_mapping_for_address(addr)
    if not mmap:
        raise ValueError()
    if hasattr(mmap, '_context'):
        # print '** _context exists'
        return mmap._context
    finder = memory_handler.get_heap_finder()
    if mmap not in finder.get_heap_mappings():  # addr is not a heap addr,
        found = False
        # or its in a child heap (win7)
        for h in finder.get_heap_mappings():
            if hasattr(h, '_children'):
                if mmap in h._children:
                    found = True
                    mmap = h
                    break
        if not found:
            raise ValueError
    try:
        ctx = ReverserContext.cacheLoad(memory_handler)#, memory_handler.get_name())
        # print '** CACHELOADED'
    except IOError as e:
        ctx = ReverserContext(memory_handler, mmap)#, memory_handler.get_name())
        # print '** newly loaded '
    # cache it
    log.debug('get_context_for_address end')
    mmap._context = ctx
    return ctx

if __name__ == '__main__':
    pass
