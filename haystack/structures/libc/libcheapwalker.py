# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loïc Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import sys

from haystack.structures import heapwalker

log = logging.getLogger('libcheapwalker')


class LibcHeapWalker(heapwalker.HeapWalker):

    """Helper class that returns heap allocations and free chunks in a standard libc process heap """

    def __init__(self, memory_handler, heap_mapping, ctypes_malloc):
        super(LibcHeapWalker, self).__init__(memory_handler, heap_mapping)
        self._ctypes_malloc = ctypes_malloc

    def _init_heap(self):
        log.debug('+ Heap @%x size: %d # %s' %
                  (self._mapping.start, len(self._mapping), self._mapping))
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
        self._allocs, self._free_chunks = self._ctypes_malloc.get_user_allocations(
            self._memory_handler, self._mapping)


class LibcHeapFinder(heapwalker.HeapFinder):

    # def _is_heap(self, _memory_handler, mapping):
    #    """test if a mapping is a heap - at least one allocation."""
    #    if not super(LibcHeapFinder,self)._is_heap(_memory_handler, mapping):
    #        return False
    #    # try to get at least one alloc.
    #    from haystack.structures.libc.ctypes_malloc import iter_user_allocations
    #    for x in iter_user_allocations(_memory_handler, mapping):
    #        return True
    #    return False

    # FIXME load unload ctypes
    def _init_heap_type(self):
        module_name = 'haystack.structures.libc.ctypes_malloc'
        real_ctypes = sys.modules['ctypes']
        sys.modules['ctypes'] = self._ctypes
        if module_name in sys.modules:
            del sys.modules[module_name]
        from haystack.structures.libc import ctypes_malloc
        self._ctypes_malloc_module = ctypes_malloc
        self._memory_handler.get_model().registerModule(sys.modules[__name__])
        # FIXME debug and TU this to be sure it is removed from modules
        if module_name in sys.modules:
            del sys.modules[module_name]
        sys.modules['ctypes'] = real_ctypes
        return self._ctypes_malloc_module.malloc_chunk

    def _init_heap_validation_depth(self):
        return 20

    def get_heap_mappings(self):
        """return the list of heaps that load as heaps

        Full overload of parent, to fix some bugs and prioritize.
        """
        heap_mappings = []
        for mapping in self._memory_handler:
            # BUG: python-ptrace read /proc/$$/mem.
            # file.seek does not like long integers like the start address
            # of the vdso or vsyscall mappigns
            if mapping.pathname in ['[vdso]', '[vsyscall]']:
                log.debug('Ignore system mapping %s', mapping)
            elif self._is_heap(mapping):
                heap_mappings.append(mapping)
        heap_mappings.sort(key=lambda m: m.start)
        # FIXME, isn't there a find() ?
        i = [
            i for (
                i,
                m) in enumerate(heap_mappings) if m.pathname == '[heap]']
        if len(i) == 1:
            h = heap_mappings.pop(i[0])
            heap_mappings.insert(0, h)
        return heap_mappings

    def get_heap_walker(self, heap):
        raise LibcHeapWalker(self._memory_handler, heap, self._ctypes_malloc_module)
