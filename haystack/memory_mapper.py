#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time

from haystack import dbg
from haystack import dump_loader
from haystack.abc import interfaces
from haystack.mappings import process
from haystack.mappings import vol
from haystack.mappings import rek

log = logging.getLogger('mapper')


class MemoryHandlerFactory(interfaces.IMemoryLoader):

    """Build MemoryMappings from a PID or a haystack memory dump."""

    def __init__(self, pid=None, mmap=True, memfile=None,
                 baseOffset=None, dumpname=None, volname=None, rekallname=None):
        memory_handler = None
        if volname is not None and pid is not None:
            mapper = vol.VolatilityProcessMapper(volname, "WinXPSP2x86", pid)
            memory_handler = mapper.make_memory_handler()
        elif rekallname is not None and pid is not None:
            mapper = rek.RekallProcessMapper(volname, pid)
            memory_handler = mapper.make_memory_handler()
        elif not (dumpname is None):
            loader = dump_loader.ProcessMemoryDumpLoader(dumpname)
            memory_handler = loader.make_memory_handler()
        elif not (pid is None):
            memory_handler = self._init_pid(pid, mmap)
        self.__memory_handler = memory_handler
        return

    def make_memory_handler(self):
        """
        Returns the instanciated MemoryHandler

        :rtype : IMemoryHandler
        """
        return self.__memory_handler

    @staticmethod
    def _init_pid(pid, mmap):
        if not isinstance(pid, (int, long)):
            raise TypeError('PID should be a number')
        my_debugger = dbg.get_debugger(pid)
        _memory_handler = process.readProcessMappings(my_debugger.get_process())
        t0 = time.time()
        for m in _memory_handler:
            if mmap:
                # force to mmap the memory in local space
                m.mmap()
                log.debug('mmap() : %d' % (len(m.mmap())))
        if mmap:
            # mmap done, we can release process...
            my_debugger.get_process().resume()
            log.info('MemoryHandler mmaped, process released after %02.02f secs', time.time() - t0)
        return _memory_handler
