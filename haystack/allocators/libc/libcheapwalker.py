# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loïc Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import sys

import os

from haystack import constraints
from haystack.abc import interfaces
from haystack.search import searcher
from haystack.allocators import heapwalker

log = logging.getLogger('libcheapwalker')


class LibcHeapWalker(heapwalker.HeapWalker):

    """Helper class that returns heap allocations and free chunks in a standard libc process heap """

    def _init_heap(self):
        log.debug('+ Heap @%x size: %d # %s' %
                  (self._heap_mapping.start, len(self._heap_mapping), self._heap_mapping))
        self._allocs = None
        self._free_chunks = None
        assert hasattr(self._heap_module, 'malloc_chunk')
        self._heap_validator = self._heap_module.LibcHeapValidator(self._memory_handler, self._heap_module_constraints, self._heap_module)

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
        self._allocs, self._free_chunks = self._heap_validator.get_user_allocations(self._heap_mapping)


    def get_heap_validator(self):
        if self._heap_validator is None:
            self._heap_validator = self._heap_module.LibcHeapValidator(self._memory_handler,
                                                   self._heap_module_constraints,
                                                   self._heap_module)
        return self._heap_validator


class LibcHeapFinder(heapwalker.HeapFinder):

    # def _is_heap(self, _memory_handler, mapping):
    #    """test if a mapping is a heap - at least one allocation."""
    #    if not super(LibcHeapFinder,self)._is_heap(_memory_handler, mapping):
    #        return False
    #    # try to get at least one alloc.
    #    from haystack.allocators.libc.ctypes_malloc import iter_user_allocations
    #    for x in iter_user_allocations(_memory_handler, mapping):
    #        return True
    #    return False

    def __init__(self, memory_handler):
        """
        :param memory_handler: IMemoryHandler
        :return: HeapFinder
        """
        super(LibcHeapFinder, self).__init__(memory_handler)
        heap_module_name = 'haystack.allocators.libc.ctypes_malloc'
        self._heap_module = self._memory_handler.get_model().import_module(heap_module_name)
        self._heap_name = 'malloc_chunk'
        self._heap_record = getattr(self._heap_module, self._heap_name)

        parser = constraints.ConstraintsConfigHandler()
        constraint_filename = os.path.join(os.path.dirname(sys.modules[__name__].__file__), 'libcheap.constraints')
        log.debug('constraint_filename :%s', constraint_filename)
        self._constraints = parser.read(constraint_filename)

        return

    def search_heap_direct(self, start_address_mapping):
        """
        return a ctypes heap struct mapped at address on the mapping
        Will use the memory handler
        """
        heap = self._memory_handler.get_mapping_for_address(start_address_mapping)
        my_searcher = searcher.AnyOffsetRecordSearcher(self._memory_handler,
                                                       self._constraints,
                                                       [heap])
        # on ly return first results in each mapping
        log.debug("_search_heap_direct in %s", start_address_mapping)
        results = my_searcher._load_at(heap, start_address_mapping, self._heap_record, depth=20)
        return results

    def _find_heap(self, mapping):
        """
        return a ctypes heap struct mapped at address on the mapping.
        """
        if self.__is_heap(mapping):
            return self.get_heap_walker(mapping)
        return None

    def __is_heap(self, mapping):
        """
        test if a mapping is a heap
        :param mapping: IMemoryMapping
        :return:
        """
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        walker = self.get_heap_walker(mapping)
        heap = mapping.read_struct(mapping.start, self._heap_record)
        # validator is (should be) then target-bound
        validator = walker.get_heap_validator()
        load = validator.load_members(heap, 20)
        log.debug('HeapFinder._is_heap %s %s', mapping, load)
        return load

    def list_heap_walkers(self):
        """return the list of heaps that load as heaps

        Full overload of parent, to fix some bugs and prioritize.
        """
        heap_walkers = []
        for mapping in self._memory_handler:
            # BUG: python-ptrace read /proc/$$/mem.
            # file.seek does not like long integers like the start address
            # of the vdso or vsyscall mappigns
            if mapping.pathname in ['[vdso]', '[vsyscall]']:
                log.debug('Ignore system mapping %s', mapping)
            else:
                walker = self._find_heap(mapping)
                if walker is not None:
                    heap_walkers.append(walker)
        # heap_walkers.sort(key=lambda m: m.start)

        # FIXME, put the [heap] in front
        i = [i for (i, walker) in enumerate(heap_walkers) if walker._heap_mapping.pathname == '[heap]']
        if len(i) == 1:
            h = heap_walkers.pop(i[0])
            heap_walkers.insert(0, h)
        return heap_walkers

    def get_heap_walker(self, mapping):
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        target_platform = self._memory_handler.get_target_platform()
        return LibcHeapWalker(self._memory_handler, target_platform, self._heap_module, mapping, self._constraints, mapping.start)
