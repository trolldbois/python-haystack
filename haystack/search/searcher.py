# -*- coding: utf-8 -*-

import logging
import time

from haystack.abc import interfaces
from haystack import utils

log = logging.getLogger('searcher')

class RecordSearcher(object):
    """ Generic structure finder.
    Will search a structure defined by it's pointer and other constraints.
    """

    def __init__(self, memory_handler, target_mappings=None, update_cb=None):
        """
        if target_mappings is not specified, the search perimeter will include
        only heap mapping.

        :param memory_handler: IMemoryHandler
        :param target_mappings: list of IMemoryMapping.
        :param update_cb: callback function to call for each valid result
        :return:
        """
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if target_mappings is not None and not isinstance(target_mappings, list):
            raise TypeError("Feed me a list of IMemoryMapping")
        elif target_mappings is None:
            # default to all heaps
            target_mappings = memory_handler.get_heap_finder().get_heap_mappings()
        self.__memory_handler = memory_handler
        self.__target_mappings = target_mappings
        self.__update_cb = update_cb
        log.debug(
            'StructFinder created for %s. Search Perimeter on %d mappings.',
            self.__memory_handler.name,
            len(self.__target_mappings))
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
        for m in self.__target_mappings:
            outputs.extend(
                self._search_in(
                    m,
                    struct_type,
                    nb=max_res-len(outputs),
                    depth=max_depth))
            # check out
            if len(outputs) >= max_res:
                break
        # if we mmap, we could yield
        return outputs

    def _search_in(self, mem_map, struct_type, nb=10, depth=99):
        """
            Looks for structType instances in memory, using :
                hints from structType (default values, and such)
                guessing validation with instance(structType)().isValid()
                and confirming with instance(structType)().loadMembers()

            returns POINTERS to structType instances.
        """
        log.debug('Looking at %s (%x bytes)', mem_map, len(mem_map))
        log.debug('look for %s', str(struct_type))
        # where do we look
        start = mem_map.start
        end = mem_map.end
        # check the word size to use aligned words only
        plen = self.__memory_handler.get_target_platform().get_word_size()
        # the struct cannot fit after that point.
        my_ctypes = self.__memory_handler.get_target_platform().get_target_ctypes()
        end = end - my_ctypes.sizeof(struct_type)
        if end <= start:
            raise ValueError("The record is too big for this memory mapping")
        log.debug("scanning 0x%lx --> 0x%lx %s every %d bytes", start, end, mem_map.pathname, plen)
        # prepare return values
        outputs = []
        # parse for structType on each aligned word
        t0 = time.time()
        p = 0
        # python 2.7 xrange doesn't handle long int. replace with ours.
        for offset in utils.xrange(start, end, plen):
            # print a debug message every now and then
            if offset % (1024 << 6) == 0:
                p2 = offset - start
                log.debug('processed %d bytes    - %02.02f test/sec',
                          p2, (p2 - p) / (plen * (time.time() - t0)))
                t0 = time.time()
                p = p2
            # a - load and validate the record
            instance, validated = self._load_at(
                mem_map, offset, struct_type, depth)
            if validated:
                log.debug("found instance @ 0x%lx", offset)
                # do stuff with it.
                self.__update_cb(instance, offset)
                outputs.append((instance, offset))
                # stop when time to stop
                if len(outputs) >= nb:
                    log.debug('_search_in: Found enough instance.')
                    break
        return outputs

    def _load_at(self, mem_map, offset, struct_type, depth=99):
        """
            loads a haystack ctypes structure from a specific offset.
                return (instance,validated) with instance being the
                haystack ctypes structure instance and validated a boolean True/False.
        """
        log.debug("Loading %s from 0x%lx " % (struct_type, offset))
        instance = mem_map.read_struct(offset, struct_type)
        # check if data matches
        if instance.loadMembers(self.__memory_handler, depth):
            log.info("found instance %s @ 0x%lx", struct_type, offset)
            # do stuff with it.
            validated = True
        else:
            log.debug("Address not validated")
            validated = False
        return instance, validated
