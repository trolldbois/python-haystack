# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging

from haystack.abc import interfaces

log = logging.getLogger('heapwalker')

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class HeapWalker(interfaces.IHeapWalker):

    def __init__(self, memory_handler, heap_mapping):
        self._memory_handler = memory_handler
        self._mapping = heap_mapping
        self._init_heap()

    def _init_heap(self):
        """ Initialiaze anything"""
        raise NotImplementedError('Please implement all methods')

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def get_free_chunks(self):
        """ returns all free chunks in the heap (addr,size) """
        raise NotImplementedError('Please implement all methods')

class HeapFinder(interfaces.IHeapFinder):

    def __init__(self, memory_handler):
        """
        :param memory_handler: IMemoryHandler
        :return: HeapFinder
        """
        assert isinstance(memory_handler, interfaces.IMemoryHandler)
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()
        self._ctypes = self._target.get_target_ctypes()
        self._heap_type = self._init_heap_type()
        self._heap_validation_depth = self._init_heap_validation_depth()

    def _init_heap_type(self):
        """init the internal heap structure type
        :rtype: ctypes heap structure type
        """
        raise NotImplementedError(self)

    def _init_heap_validation_depth(self):
        """init the internal heap structure type
        :rtype: ctypes heap structure type
        """
        raise NotImplementedError(self)

    def _read_heap(self, mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        addr = mapping.start
        heap = mapping.read_struct(addr, self._heap_type)
        return heap

    def _is_heap(self, mapping):
        """test if a mapping is a heap"""
        from haystack.mappings import base
        if not isinstance(self._memory_handler, base.MemoryHandler):
            raise TypeError('Feed me a Mappings object')
        heap = self._read_heap(mapping)
        load = heap.loadMembers(self._memory_handler, self._heap_validation_depth)
        log.debug('HeapFinder._is_heap %s %s' % (mapping, load))
        return load

    def get_heap_mappings(self):
        """return the list of heaps that load as heaps"""
        heap_mappings = []
        for mapping in self._memory_handler:
            if self._is_heap(mapping):
                heap_mappings.append(mapping)
        heap_mappings.sort(key=lambda m: m.start)
        return heap_mappings

    def get_heap_walker(self, heap):
        raise NotImplementedError(self)


def make_heap_finder(memory_handler):
    """
    Build a heap_finder for this memory_handler

    :param memory_handler: IMemoryHandler
    :return: a heap walker for that platform
    :rtype: IHeapWalker
    """
    if not isinstance(memory_handler, interfaces.IMemoryHandler):
        raise TypeError('memory_handler should be an IMemoryHandler')
    target_platform = memory_handler.get_target_platform()
    os_name = target_platform.get_os_name()
    if os_name == 'linux':
        from haystack.structures.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder(memory_handler)
    elif os_name == 'winxp':
        from haystack.structures.win32 import winheapwalker
        return winheapwalker.WinHeapFinder(memory_handler)
    elif os_name == 'win7':
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder(memory_handler)
    else:
        raise NotImplementedError(
            'Heap Walker not found for os %s', os_name)