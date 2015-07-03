#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging
from haystack.abc import interfaces
log = logging.getLogger('heapwalker')

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class HeapWalker(interfaces.IHeapWalker):

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


class HeapFinder(interfaces.IHeapFinder):

    def __init__(self, target):
        """
        :param target: ITargetPlatform
        :return:
        """
        self._target = target
        self._ctypes = self._target.get_target_ctypes()
        self.__heap_type = self._init_heap_type()
        self.__walker_class = self._init_walker_class()
        # FIXME to method
        self.heap_validation_depth = 1

    def _init_heap_type(self):
        """returns the internal heap structure type
        :rtype: ctypes heap structure type
        """
        raise NotImplementedError(self)

    def _init_walker_class(self):
        """returns the heap walker type
        :rtype: IHeapWalker
        """
        raise NotImplementedError(self)

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
        heap = mapping.read_struct(addr, self.__heap_type)
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

    def get_heap_type(self):
        """
        return the ctype of the heap structure

        :return: ctypes
        """
        return self.__heap_type

    def get_heap_walker(self, mappings, heap):
        return self.__walker_class(mappings, heap, 0)



def make_heap_finder(target):
    """
    Build a heap_finder for this target

    :param target: ITargetPlatform
    :return: a heap walker for that platform
    :rtype: IHeapWalker
    """
    if not isinstance(target, interfaces.ITargetPlatform):
        raise TypeError('target should be an ITargetPlatform')
    # ctypes is preloaded with proper arch
    os_name = target.get_os_name()
    if os_name == 'linux':
        from haystack.structures.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder(target)
    elif os_name == 'winxp':
        from haystack.structures.win32 import winheapwalker
        return winheapwalker.WinHeapFinder(target)
    elif os_name == 'win7':
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder(target)
    else:
        raise NotImplementedError(
            'Heap Walker not found for os %s' %
            (os_name))