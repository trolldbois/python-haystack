#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging

log = logging.getLogger('heapwalker')

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class HeapWalker(object):

    def __init__(self, mappings, mapping, offset=0):
        self._mappings = mappings
        self._mapping = mapping
        self._offset = offset
        self._init_heap()

    def _init_heap(self):
        raise NotImplementedError('Please implement all methods')

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def get_free_chunks(self):
        """ returns all free chunks in the heap (addr,size) """
        raise NotImplementedError('Please implement all methods')


# TODO make a virtual function that plays libc or win32 ?
# or put that in the MemoryMappings ?
# or in the context ?


class HeapFinder(object):

    def __init__(self):#, ctypes):
        #ctypes = types.set_ctypes(ctypes)
        self.heap_type = None
        self.walker_class = callable()
        self.heap_validation_depth = 1
        raise NotImplementedError(
            'Please fix your self.heap_type and self.walker_class')

    def is_heap(self, mappings, mapping):
        """test if a mapping is a heap"""
        from haystack.mappings import base
        if not isinstance(mappings, base.MemoryHandler):
            raise TypeError('Feed me a Mappings object')
        heap = self.read_heap(mapping)
        load = heap.loadMembers(mappings, self.heap_validation_depth)
        log.debug('HeapFinder.is_heap %s %s' % (mapping, load))
        return load

    def read_heap(self, mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        addr = mapping.start
        heap = mapping.read_struct(addr, self.heap_type)
        return heap

    def get_heap_mappings(self, mappings):
        """return the list of heaps that load as heaps"""
        from haystack.mappings import base
        if not isinstance(mappings, base.MemoryHandler):
            raise TypeError('Feed me a Mappings object')
        heap_mappings = []
        for mapping in mappings:
            # BUG: python-ptrace read /proc/$$/mem.
            # file.seek does not like long integers
            if mapping.pathname in ['[vdso]', '[vsyscall]']:
                log.debug('Ignore system mapping %s' % (mapping))
            elif self.is_heap(mappings, mapping):
                heap_mappings.append(mapping)
        heap_mappings.sort(key=lambda m: m.start)
        return heap_mappings

    def get_walker_for_heap(self, mappings, heap):
        return self.walker_class(mappings, heap, 0)


def make_heap_walker(mappings):
    """try to find what type of heaps are """
    from haystack.mappings import base
    if not isinstance(mappings, base.MemoryHandler):
        raise TypeError('Feed me a Mappings')
    # ctypes is preloaded with proper arch
    os_name = mappings.get_os_name()
    if os_name == 'linux':
        from haystack.structures.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder()
    elif os_name == 'winxp':
        from haystack.structures.win32 import winheapwalker
        return winheapwalker.WinHeapFinder()
    elif os_name == 'win7':
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder()
    else:
        raise NotImplementedError(
            'Heap Walker not found for os %s' %
            (os_name))