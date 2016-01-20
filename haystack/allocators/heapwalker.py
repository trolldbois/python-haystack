# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging

from haystack.abc import interfaces
from haystack import constraints
from haystack.search import searcher

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
        self._heap_module_name, self._heap_class_name, self._heap_constraint_filename = self._init()
        self._heap_module = self._import_heap_module()
        self._heap_module_constraints = self._load_heap_constraints()
        self._heap_validation_depth = self._init_heap_validation_depth()
        self._heap_type = self._init_heap_type()
        # optimisations
        self.__optim_heaps = None

    def _init(self):
        """
        Return the heap configuration information
        :return: (heap_module_name, heap_class_name, heap_constraint_filename)
        """
        raise NotImplementedError(self)

    def _import_heap_module(self):
        """
        Load the module for this target arch
        :return: module
        """
        heap_module = self._memory_handler.get_model().import_module(self._heap_module_name)
        # FIXME, is that necessary for memory allocation structs ?
        # not needed
        # self._memory_handler.get_model().build_python_class_clones(heap_module)
        return heap_module

    def _load_heap_constraints(self):
        """
        Init the constraints on the heap module
        :return:
        """
        parser = constraints.ConstraintsConfigHandler()
        return parser.read(self._heap_constraint_filename)

    def _init_heap_type(self):
        """init the internal heap structure type
        :rtype: ctypes heap structure type
        """
        return getattr(self._heap_module, self._heap_class_name)

    def _init_heap_validation_depth(self):
        """init the internal heap structure type
        :rtype: ctypes heap structure type
        """
        return 1

    def _search_heap(self, mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        my_searcher = searcher.AnyOffsetRecordSearcher(self._memory_handler,
                                                       self._heap_module_constraints)
        # on ly return first results in each mapping
        log.debug("_search_heap in %s", mapping)
        res = my_searcher._search_in(mapping, self._heap_type, nb=1, align=0x1000)
        # DEBUG PEB search
        # res = my_searcher._search_in(mapping, peb.struct__PEB, nb=1, align=0x1000)
        if len(res) > 0:
            instance, address = res[0]
            mapping.mark_as_heap(address)
            return instance, address
        return None

    def search_heap(self):
        # on ly return first results in each mapping
        results = []
        for mapping in self._memory_handler.get_mappings():
            res = self._search_heap(mapping)
            if res:
                results.append(res)
        return results

    def search_heap_direct(self, start_address_mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        m = self._memory_handler.get_mapping_for_address(start_address_mapping)
        my_searcher = searcher.AnyOffsetRecordSearcher(self._memory_handler,
                                                       self._heap_module_constraints,
                                                       [m])
        # on ly return first results in each mapping
        log.debug("_search_heap_direct in %s", start_address_mapping)
        results = my_searcher._load_at(m, start_address_mapping, self._heap_type, depth=5)
        return results

    def _read_heap(self, mapping, addr):
        """ return a ctypes heap struct mapped at address on the mapping"""
        heap = mapping.read_struct(addr, self._heap_type)
        return heap

    def _is_heap(self, mapping, addr):
        raise NotImplementedError(self)

    def list_heap_walkers(self):
        raise NotImplementedError(self)

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
