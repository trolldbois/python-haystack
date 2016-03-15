# -*- coding: utf-8 -*-

import logging
import time

from haystack.abc import interfaces
from haystack import utils
from haystack import listmodel

log = logging.getLogger('searcher')


class RecordSearcher(object):
    """
    Generic record type searcher.
    Will search a record (Structure, Union) defined by it's member types, pointer and other constraints.
    """

    def __init__(self, memory_handler, my_constraints=None, target_mappings=None, update_cb=None):
        """
        if target_mappings is not specified, the search perimeter will include
        only heap mapping.

        :param memory_handler: interfaces.IMemoryHandler
        :param target_mappings: list of interfaces.IMemoryMapping.
        :param my_constraints: interfaces.IModuleConstraints
        :param update_cb: callback function to call for each valid result
        :return:
        """
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if my_constraints and not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        if target_mappings is not None and not isinstance(target_mappings, list):
            raise TypeError("Feed me a list of IMemoryMapping")
        elif target_mappings is None:
            # default to all heaps
            target_walkers = memory_handler.get_heap_finder().list_heap_walkers()
            target_mappings = [walker.get_heap_mapping() for walker in target_walkers]
        self._memory_handler = memory_handler
        self._my_constraints = my_constraints
        self._target_mappings = target_mappings
        self._update_cb = update_cb
        log.debug('RecordSearcher created for %s. Search Perimeter on %d mappings.',
                    self._memory_handler.get_name(),
                    len(self._target_mappings))
        return

    def search(self, struct_type, max_res=10, max_depth=10):
        """
        Iterate on the process memory to find a specific structure.
        If constraints have been applied to the struct_type, they will will enforced.

        :param struct_type: ctypes.Structure or ctypes.Union
        :param max_res: the maximum number of returned results
        :param max_depth: the maximum depth of recursive validation in a record
        :return:
        """
        outputs = []
        for m in self._target_mappings:
            outputs.extend(self._search_in(m, struct_type, nb=max_res-len(outputs), depth=max_depth))
            # check out
            if len(outputs) >= max_res:
                break
        # if we mmap, we could yield
        return outputs

    def _search_in(self, mem_map, struct_type, nb=10, depth=99):
        """
            Looks for structType instances in memory, using :
                hints from structType (default values, and such)
                guessing validation with Validator.isValid(instance)
                and confirming with a Validator.load_members(instance)

            we only look for user memory allocation chunks matching the
            size of the structure.

            returns POINTERS to structType instances.
        """
        log.debug('Looking at %s (%x bytes)', mem_map, len(mem_map))
        log.debug('look for %s', str(struct_type))
        # prepare return values
        outputs = []
        # where do we look for that structure
        finder = self._memory_handler.get_heap_finder()
        walker = finder.get_heap_walker(mem_map)
        # check the word size to use aligned words only
        target = walker.get_target_platform()
        plen = target.get_word_size()
        my_ctypes = target.get_target_ctypes()
        struct_size = my_ctypes.sizeof(struct_type)
        # get all allocated chunks
        for addr, size in walker.get_user_allocations():
            # FIXME, heap walker should give a hint
            # minimum chunk size varies...
            if size < struct_size:
                log.debug("size %d < struct_size %d", size, struct_size)
                continue
            log.debug("testing 0x%lx", addr)
            # could change
            mem_map = self._memory_handler.get_mapping_for_address(addr)
            # try every aligned offset from there to the end of chunk
            start = addr
            end = start + size - struct_size + 1
            # check if there is room (if size < struct_size)
            if end < start:
                log.debug('end < start')
                continue
            log.debug('xrange(%d, %d, %d) ', start, end, plen)
            for offset in utils.xrange(start, end, plen):
                # a - load and validate the record
                log.debug('load_at(%d) ', offset)
                instance, validated = self._load_at(mem_map, offset, struct_type, depth)
                if validated:
                    log.debug("found instance @ 0x%lx", offset)
                    # do stuff with it.
                    if self._update_cb is not None:
                        self._update_cb(instance, offset)
                    outputs.append((instance, offset))
                    # stop when time to stop
                    if len(outputs) >= nb:
                        log.debug('_search_in: Found enough instance.')
                        break
        return outputs

    def _load_at(self, mem_map, address, struct_type, depth=99):
        """
            loads a haystack ctypes structure from a specific offset.
                return (instance,validated) with instance being the
                haystack ctypes structure instance and validated a boolean True/False.
        """
        log.debug("Loading %s from 0x%lx " % (struct_type, address))
        instance = mem_map.read_struct(address, struct_type)
        log.debug("Validating %s from 0x%lx " % (struct_type, address))
        validator = listmodel.ListModel(self._memory_handler, self._my_constraints)
        # check if data matches
        if validator.load_members(instance, depth):
            # FIXME: should be if validator.is_valid(instance):
            log.debug("found instance %s @ 0x%lx", struct_type, address)
            # do stuff with it.
            validated = True
        else:
            log.debug("Address not validated")
            validated = False
        return instance, validated


class RecordLoader(RecordSearcher):
    """
    Generic record loader.
    Will load a record from a specific address.
    """

    def load(self, struct_type, memory_address):
        # get the heap
        mem_map = self._memory_handler.get_mapping_for_address(memory_address)
        return self._load_at(mem_map, memory_address, struct_type)


class AnyOffsetRecordSearcher(RecordSearcher):
    """
    This searcher will not use heap helpers and search will not be restricted to
    allocated chunks of memory.
    """
    def __init__(self, memory_handler, my_constraints=None, target_mappings=None, update_cb=None):
        """
        if target_mappings is not specified, the search perimeter will include
        only heap mapping.

        :param memory_handler: interfaces.IMemoryHandler
        :param target_mappings: list of interfaces.IMemoryMapping.
        :param my_constraints: interfaces.IModuleConstraints
        :param update_cb: callback function to call for each valid result
        :return:
        """
        if target_mappings is None:
            # default to all heaps
            target_mappings = memory_handler.get_mappings()
        super(AnyOffsetRecordSearcher, self).__init__(memory_handler, my_constraints, target_mappings, update_cb)
        return

    def _search_in(self, mem_map, struct_type, nb=10, depth=99, align=None):
        """
            Looks for structType instances in memory, using :
                hints from structType (default values, and such)
                guessing validation with Validator.isValid(instance)
                and confirming with a Validator.load_members(instance)

            returns POINTERS to structType instances.
        """
        log.debug('Looking at %s (%x bytes)', mem_map, len(mem_map))
        log.debug('look for %s', str(struct_type))
        # where do we look
        start = mem_map.start
        end = mem_map.end
        # pointer len for alignment
        plen = mem_map.get_target_platform().get_word_size()
        # # check the word size to use aligned words only
        if align is None:
            align = plen
        else:
            align = align - align % plen
        # the struct cannot fit after that point.
        my_ctypes = mem_map.get_target_platform().get_target_ctypes()
        end = end - my_ctypes.sizeof(struct_type) + 1
        if end <= start:
            raise ValueError("The record is too big for this memory mapping")
        log.debug("scanning 0x%lx --> 0x%lx %s every %d bytes", start, end, mem_map.pathname, plen)
        # prepare return values
        outputs = []
        # parse for structType on each aligned word
        t0 = time.time()
        p = 0
        # python 2.7 xrange doesn't handle long int. replace with ours.
        for offset in utils.xrange(start, end, align):
            # print a debug message every now and then
            if offset % (1024 << 6) == 0:
                p2 = offset - start
                log.debug('processed %d bytes    - %02.02f test/sec', p2, (p2 - p) / (plen * (time.time() - t0)))
                t0 = time.time()
                p = p2
            # a - load and validate the record
            instance, validated = self._load_at(mem_map, offset, struct_type, depth)
            if validated:
                log.debug("found instance @ 0x%lx", offset)
                # do stuff with it.
                if self._update_cb is not None:
                    self._update_cb(instance, offset)
                outputs.append((instance, offset))
                # stop when time to stop
                if len(outputs) >= nb:
                    log.debug('_search_in: Found enough instance.')
                    break
        return outputs
