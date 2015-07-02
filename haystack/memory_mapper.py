#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Gets memory mappings from a PID or a haystack dump."""

import logging
import time

import os

from haystack.dbg import PtraceDebugger
from haystack import config
from haystack import dump_loader
from haystack.abc import interfaces
from haystack.mappings import base
from haystack.mappings.file import FileBackedMemoryMapping
from haystack.mappings.file import MemoryDumpMemoryMapping
from haystack.mappings.process import readProcessMappings
from haystack.mappings.vol import VolatilityProcessMapper

log = logging.getLogger('mapper')

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class MemoryHandlerFactory(interfaces.IMemoryLoader):

    """Build MemoryMappings from a PID or a haystack memory dump."""

    def __init__(self, pid=None, mmap=True, memfile=None,
                 baseOffset=None, dumpname=None, volname=None):
        memory_handler = None
        if not (volname is None) and not (pid is None):
            memory_handler = self._init_volatility(dumpname, pid)
        if not (pid is None):
            memory_handler = self._init_pid(pid, mmap)
        elif not (memfile is None):
            memory_handler = self._init_memfile(memfile, baseOffset)
        elif not (dumpname is None):
            memory_handler = self._init_process_dumpfile(dumpname)
        self.__memory_handler = memory_handler
        return

    def make_memory_handler(self):
        """Creates a MemoryHandler

        :rtype : IMemoryHandler
        """
        return self.__memory_handler

    @staticmethod
    def _init_process_dumpfile(dumpname):
        loader = dump_loader.ProcessMemoryDumpLoader(dumpname)
        mappings = loader.make_memory_handler()
        return mappings

    @staticmethod
    def _init_memfile(memfile, baseOffset):
        size = os.fstat(memfile.fileno()).st_size
        if size > config.MAX_MAPPING_SIZE_FOR_MMAP:
            mem = FileBackedMemoryMapping(
                memfile,
                baseOffset,
                baseOffset +
                size)  # is that valid ?
            log.warning(
                'Dump file size is big. Using file backend memory mapping. Its gonna be slooow')
        else:
            mem = MemoryDumpMemoryMapping(
                memfile,
                baseOffset,
                baseOffset +
                size)  # is that valid ?
        mappings = base.MemoryHandler([mem], memfile.name)
        return mappings

    @staticmethod
    def _init_pid(pid, mmap):
        if not isinstance(pid, (int, long)):
            raise TypeError('PID should be a number')
        dbg = PtraceDebugger()
        process = dbg.addProcess(pid, is_attached=False)
        if process is None:
            log.error("Error initializing Process debugging for %d" % pid)
            raise IOError
            # ptrace exception is raised before that
        mappings = readProcessMappings(process)
        t0 = time.time()
        for m in mappings:
            if mmap:
                # mmap memory in local space
                m.mmap()
                log.debug('mmap() : %d' % (len(m.mmap())))
        if mmap:
            # mmap done, we can release process...
            process.cont()
            log.info(
                'MemoryHandler mmaped, process released after %02.02f secs' %
                (time.time() - t0))
        return mappings

    @staticmethod
    def _init_volatility(volname, pid):
        mapper = VolatilityProcessMapper(volname, pid)
        mappings = mapper.getMappings()
        return mappings
