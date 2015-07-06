#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Provides memory mapping wrappers for live processes.

Classes:
- ProcessMemoryMapping: memory space from a live process with the possibility to mmap the memspace at any moment.
"""

import logging
from weakref import ref

import os
import re

from haystack.dbg import openProc, ProcError, ProcessError, HAS_PROC
from haystack import utils
from haystack import target
from haystack.structures import heapwalker
from haystack.mappings.base import MemoryHandler, AMemoryMapping
from haystack.mappings.file import LocalMemoryMapping

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('process')

PROC_MAP_REGEX = re.compile(
    # Address range: '08048000-080b0000 '
    r'([0-9a-f]+)-([0-9a-f]+) '
    # Permission: 'r-xp '
    r'(.{4}) '
    # Offset: '0804d000'
    r'([0-9a-f]+) '
    # Device (major:minor): 'fe:01 '
    r'([0-9a-f]{2}):([0-9a-f]{2}) '
    # Inode: '3334030'
    r'([0-9]+)'
    # Filename: '    /usr/bin/synergyc'
    r'(?: +(.*))?')


class ProcessMemoryMapping(AMemoryMapping):

    """
    Process memory mapping (metadata about the mapping).

    Attributes:
     - _process: weak reference to the process
     - _local_mmap: the LocalMemoryMapping is mmap() has been called
     _ _base: the current MemoryMapping reader ( process or local_mmap )

    Operations:
     - "mmap" mmap the MemoryMap to local address space
     - "readWord()": read a memory word, from local mmap-ed memory if mmap-ed
     - "readBytes()": read some bytes, from local mmap-ed memory if mmap-ed
     - "readStruct()": read a structure, from local mmap-ed memory if mmap-ed
     - "readArray()": read an array, from local mmap-ed memory if mmap-ed
         useful in list contexts
    """

    def __init__(self, process, start, end, permissions, offset,
                 major_device, minor_device, inode, pathname):
        AMemoryMapping.__init__(
            self,
            start,
            end,
            permissions,
            offset,
            major_device,
            minor_device,
            inode,
            pathname)
        self._process = ref(process)
        self._local_mmap = None
        self._local_mmap_content = None
        # read from process by default
        #self._base = self._process()
        self._base = process

    def read_word(self, address):
        word = self._base.read_word(address)
        return word

    def read_bytes(self, address, size):
        data = self._base.read_bytes(address, size)
        return data

    def read_struct(self, address, _struct):
        _struct = self._base.read_struct(address, _struct)
        _struct._orig_address_ = address
        return _struct

    def read_array(self, address, basetype, count):
        array = self._base.read_array(address, basetype, count)
        return array

    def isMmaped(self):
        return not (self._local_mmap is None)

    def mmap(self):
        ''' mmap-ed access gives a 20% perf increase on by tests '''
        # DO NOT USE ptrace.process.readArray on 64 bits.
        # It breaks stuff.
        # probably a bad cast statement on c_char_p
        # FIXME: the big perf increase is now gone. Howto cast pointer to bytes
        # into ctypes array ?
        ctypes = self._target_platform.get_target_ctypes()
        if not self.isMmaped():
            # self._process().readArray(self.start, ctypes.c_ubyte, len(self) ) # keep ref
            # self._local_mmap_content = self._process().readArray(self.start,
            # ctypes.c_ubyte, len(self) ) # keep ref
            self._local_mmap_content = utils.bytes2array(
                self._process().read_bytes(
                    self.start,
                    len(self)),
                ctypes.c_ubyte)
            log.debug('type array %s' % (type(self._local_mmap_content)))
            self._local_mmap = LocalMemoryMapping.fromAddress(
                self, ctypes.addressof(
                    self._local_mmap_content))
            self._base = self._local_mmap
        return self._local_mmap

    def unmmap(self):
        self._base = self._process()
        self._local_mmap = None
        self._local_mmap_content = None

    def __getstate__(self):
        d = dict(self.__dict__)
        d['_local_mmap'] = None
        d['_local_mmap_content'] = None
        d['_base'] = None
        d['_process'] = None
        return d


def readProcessMappings(process):
    """
    Read all memory _memory_handler of the specified process.

    Return a list of MemoryMapping objects, or empty list if it's not possible
    to read the _memory_handler.

    May raise a ProcessError.
    """
    maps = []
    if not HAS_PROC:
        return maps
    try:
        mapsfile = openProc(process.pid)
    except ProcError as err:
        raise ProcessError(process, "Unable to read process maps: %s" % err)

    #before = None
    # save the current ctypes module.
    mappings = []
    # FIXME Debug, but probably useless now that ctypes is in _target_platform
    #if True:
    #    import ctypes
    #    before = ctypes
    try:
        for line in mapsfile:
            line = line.rstrip()
            match = PROC_MAP_REGEX.match(line)
            if not match:
                raise ProcessError(
                    process,
                    "Unable to parse memory mapping: %r" %
                    line)
            log.debug('readProcessMappings %s' % (str(match.groups())))
            _map = ProcessMemoryMapping(
                # cfg,
                process,
                int(match.group(1), 16),
                int(match.group(2), 16),
                match.group(3),
                int(match.group(4), 16),
                int(match.group(5), 16),
                int(match.group(6), 16),
                int(match.group(7)),
                match.group(8))
            mappings.append(_map)
    finally:
        if isinstance(mapsfile, file):
            mapsfile.close()
    # reposition the previous ctypes module.
    #if True:
    #    ctypes = types.set_ctypes(before)
    _target_platform = target.TargetPlatform.make_target_platform_local()
    _memory_handler = MemoryHandler(mappings, _target_platform)
    return _memory_handler


def readLocalProcessMappings():
    class P:
        pid = os.getpid()
        # we need that for the machine arch read.

        def readBytes(self, addr, size):
            import ctypes
            return ctypes.string_at(addr, size)

    return readProcessMappings(P())  # memory_mapping
