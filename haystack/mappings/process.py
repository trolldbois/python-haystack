#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Provides memory mapping wrappers for live processes.

Classes:
- ProcessMemoryMapping: memory space from a live process with the possibility to mmap the memspace at any moment.
"""

import ctypes
import logging
from weakref import ref

import os
import re

from haystack import dbg
from haystack import target
from haystack.mappings.base import MemoryHandler, AMemoryMapping
from haystack.mappings.file import LocalMemoryMapping

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

    def is_mmaped(self):
        return not (self._local_mmap is None)

    def mmap(self):
        """
         mmap-ed access gives a 20% perf increase on by tests
        :return:
        """
        # DO NOT USE ptrace.process.readArray on 64 bits.
        # It breaks stuff.
        # probably a bad cast statement on c_char_p
        # FIXME: the big perf increase is now gone. Howto cast pointer to bytes
        # into my_ctypes array ?
        if not self.is_mmaped():
            self._local_mmap_content = self._utils.bytes2array(self._process().read_bytes(self.start, len(self)), self._ctypes.c_ubyte)
            log.debug('type array %s' % (type(self._local_mmap_content)))
            self._local_mmap = LocalMemoryMapping.fromAddress(self, self._ctypes.addressof(self._local_mmap_content))
            self._base = self._local_mmap
        return self._local_mmap

    def rebase(self, new_start_address):
        super(ProcessMemoryMapping, self).rebase(new_start_address)
        if self.is_mmaped():
            self._base.rebase(new_start_address)

    def reset(self):
        """
        Allows for this lazy-loading mapping wrapper to return
        to a non-loaded state, closing opened file descriptors.
        :return:
        """
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


def make_process_memory_handler(process):
    """
    Read all memory mappings of the specified process.

    Return a list of MemoryMapping objects, or empty list if it's not possible
    to read the memory mappings.

    May raise a ProcessError.
    """
    if not isinstance(process, dbg.IProcess):
        raise TypeError('dbg.IProcess expected')
    mapsfile = process.get_mappings_line()

    mappings = []
    is_64 = False
    # read the mappings
    for line in mapsfile:
        line = line.rstrip()
        match = PROC_MAP_REGEX.match(line)
        if not match:
            raise IOError(process, "Unable to parse memory mapping: %r" % line)
        if not is_64 and len(match.group(1)) > 8:
            is_64 = True
        #
        log.debug('readProcessMappings %s' % (str(match.groups())))
        _map = ProcessMemoryMapping(process, int(match.group(1), 16), int(match.group(2), 16),
                                    match.group(3), int(match.group(4), 16), int(match.group(5), 16),
                                    int(match.group(6), 16), int(match.group(7)), match.group(8))
        mappings.append(_map)
    # create the memory_handler for self
    import sys
    if 'linux' in sys.platform:
        os_name = target.TargetPlatform.LINUX
    else: # sys.platform.startswith('win'):
        os_name = target.TargetPlatform.WIN7
    _target_platform = None
    if is_64:
        if os_name in [target.TargetPlatform.WINXP, target.TargetPlatform.WIN7]:
            _target_platform = target.TargetPlatform.make_target_win_64(os_name)
        elif os_name == target.TargetPlatform.LINUX:
            _target_platform = target.TargetPlatform.make_target_linux_64()
    else:
        if os_name in [target.TargetPlatform.WINXP, target.TargetPlatform.WIN7]:
            _target_platform = target.TargetPlatform.make_target_win_32(os_name)
        elif os_name == target.TargetPlatform.LINUX:
            _target_platform = target.TargetPlatform.make_target_linux_32()
    _memory_handler = MemoryHandler(mappings, _target_platform, 'localhost-%d' % process.get_pid())
    return _memory_handler


__LOCAL_MAPPINGS = None


def make_local_memory_handler(force=False):
    global __LOCAL_MAPPINGS
    if __LOCAL_MAPPINGS is None or force:
        __LOCAL_MAPPINGS = make_process_memory_handler(dbg.MyPTraceProcess(os.getpid(), None))
    return __LOCAL_MAPPINGS
