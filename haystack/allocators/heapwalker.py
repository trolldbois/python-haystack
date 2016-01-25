# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging

from haystack.abc import interfaces

log = logging.getLogger('heapwalker')


class HeapWalker(interfaces.IHeapWalker):

    def __init__(self, memory_handler, target_platform, heap_module, heap_mapping, heap_module_constraints, address):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(target_platform, interfaces.ITargetPlatform):
            raise TypeError("Feed me a ITargetPlatform")
        self._memory_handler = memory_handler
        self._target = target_platform
        self._heap_module = heap_module
        self._heap_mapping = heap_mapping
        self._heap_module_constraints = heap_module_constraints
        self._address = address
        self._init_heap()

    def _init_heap(self):
        """ Initialize anything"""
        raise NotImplementedError('Please implement all methods')

    def get_target_platform(self):
        """Returns the ITargetPlatform for that process memory."""
        return self._target

    def get_heap_address(self):
        return self._address

    def get_heap(self):
        """ return the ctypes heap struct mapped at address on the mapping"""
        raise NotImplementedError('Please implement all methods')

    def get_heap_mapping(self):
        """ return the mapping containing the root HEAP record"""
        return self._heap_mapping

    def get_heap_validator(self):
        """ return the validator """
        raise NotImplementedError('Please implement all methods')

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def get_free_chunks(self):
        """ returns all free chunks in the heap (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def __contains__(self, address):
        """ Does the heap walker or its relevant segments contains this address"""
        raise NotImplementedError('Please implement all methods')


class HeapFinder(interfaces.IHeapFinder):

    def __init__(self, memory_handler):
        """
        :param memory_handler: IMemoryHandler
        :return: HeapFinder
        """
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError('Feed me a IMemoryHandlerobject')
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()
        # optimisations
        self._heap_walkers = None
        self._heap_walkers_dict = None

    def get_heap_walker(self, mapping):
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        if not self._heap_walkers_dict:
            self.list_heap_walkers()
        # BUG FIXME reverse
        if mapping.start not in self._heap_walkers_dict:
            raise ValueError('mapping not used as a heap')
        walker = self._heap_walkers_dict[mapping.start]
        return walker

    def list_heap_walkers(self):
        """return the list of heaps that load as heaps"""
        if not self._heap_walkers:
            self._heap_walkers = []
            for mapping in self._memory_handler:
                walker = self._find_heap(mapping)
                if walker:
                    self._heap_walkers.append(walker)
            # sort the list
            self._heap_walkers.sort(key=lambda walker: walker.get_heap_address())
            # FIXME, so do we have heaps in the middle of a mapping or not ?
            # FIXME: what about segments
            self._heap_walkers_dict = dict([(w.get_heap_address(), w) for w in self._heap_walkers])
        return self._heap_walkers

    def search_heap_direct(self, start_address_mapping):
        """
        return a ctypes heap struct mapped at address on the mapping
        Will use the memory handler
        """
        raise NotImplementedError(self)

    def _find_heap(self, mapping):
        """
        return a ctypes heap struct mapped at address on the mapping.
        Funny enough, a X64 process could have 32 bits and 64 bits heaps.
        """
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
        from haystack.allocators.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder(memory_handler)
    elif os_name == 'winxp':
        from haystack.allocators.win32 import winxpheapwalker
        return winxpheapwalker.WinXPHeapFinder(memory_handler)
    elif os_name == 'win7':
        from haystack.allocators.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder(memory_handler)
    else:
        raise NotImplementedError('Heap Walker not found for os %s', os_name)
