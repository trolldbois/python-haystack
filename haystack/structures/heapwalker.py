# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging

from haystack.abc import interfaces
from haystack import constraints
from haystack.search import searcher

log = logging.getLogger('heapwalker')

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class HeapWalker(interfaces.IHeapWalker):

    def __init__(self, memory_handler, heap_module, heap_mapping, heap_module_constraints):
        if not heap_mapping.is_marked_as_heap():
            raise TypeError('Please mark the mapping as heap before use')
        self._memory_handler = memory_handler
        self._heap_module = heap_module
        self._heap_mapping = heap_mapping
        self._heap_module_constraints = heap_module_constraints
        self._init_heap(heap_mapping.get_marked_heap_address())

    def _init_heap(self, address):
        """ Initialize anything"""
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
        if len(res) > 0:
            instance, address = res[0]
            mapping.mark_as_heap(address)
            return instance, address
        return None

    def _read_heap(self, mapping, addr):
        """ return a ctypes heap struct mapped at address on the mapping"""
        heap = mapping.read_struct(addr, self._heap_type)
        return heap

    def _is_heap(self, mapping, addr):
        """
        test if a mapping is a heap
        :param mapping: IMemoryMapping
        :return:
        """
        if not isinstance(mapping, interfaces.IMemoryMapping):
            raise TypeError('Feed me a IMemoryMapping object')
        if mapping.is_marked_as_heap() and addr == mapping.get_marked_heap_address():
            return True
        # we find some backend heap at other addresses
        heap = self._read_heap(mapping, addr)
        load = self.get_heap_validator().load_members(heap, self._heap_validation_depth)
        log.debug('HeapFinder._is_heap %s %s' % (mapping, load))
        return load

    def get_heap_module(self):
        """
        Returns the heap module.
        :return:
        """
        return self._heap_module

    def get_heap_mappings(self):
        """return the list of heaps that load as heaps"""
        if not self.__optim_heaps:
            self.__optim_heaps = []
            for mapping in self._memory_handler:
                # try at offset 0
                if mapping.is_marked_as_heap():
                    self.__optim_heaps.append(mapping)
                else:
                    # try harder elsewhere in the mapping
                    res = self._search_heap(mapping)
                    if res is not None:
                        self.__optim_heaps.append(mapping)
            self.__optim_heaps.sort(key=lambda m: m.start)
        return self.__optim_heaps

    def get_heap_walker(self, heap):
        raise NotImplementedError(self)

    def get_heap_validator(self):
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
        from haystack.structures.win32 import winxpheapwalker
        return winxpheapwalker.WinXPHeapFinder(memory_handler)
    elif os_name == 'win7':
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder(memory_handler)
    else:
        raise NotImplementedError(
            'Heap Walker not found for os %s', os_name)