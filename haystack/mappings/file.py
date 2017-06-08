#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

"""Provide several memory mapping wrappers to handle different situations.

Short story, the memory of a process is segmented in several memory
zones called memory mapping,
    exemple: the heap, the stack, mmap(2)-s of files, mmap(2)-ing a
             dynamic library, etc.
Theses memory mapping represent the memory space of a process. Each
mapping hasca start and a end address, which gives boundaries for the
range of valid pointer values.

There are several ways to wraps around a memory mapping, given the precise
scenario you are in. You could need a wrapper for a live process debugging, a
wrapper for a mapping that has been dumps in a file, a wrapper for a mapping
that has been remapped to memory, etc.

Classes:
- MemoryMapping : memory mapping metadata
- ProcessMemoryMapping: memory space from a live process with the possibility to mmap the memspace at any moment.
- LocalMemoryMapping .fromAddress: memorymapping that lives in local space in a ctypes buffer.
- MemoryDumpMemoryMapping .fromFile : memory space from a raw file, with lazy loading capabilities.
- FileBackedMemoryMapping .fromFile : memory space based on a file, with direct read no cache from file.

This code first 150 lines is mostly inspired by python ptrace by Haypo / Victor Skinner.
Its intended to be retrofittable with ptrace's memory _memory_handler.
"""

from past.builtins import long
import logging
import struct
import mmap

import os
import ctypes

# haystack
import haystack
from haystack import utils
from haystack.mappings import base
from haystack.mappings.base import AMemoryMapping

log = logging.getLogger('file')

MMAP_HACK_ACTIVE = True

class LocalMemoryMapping(AMemoryMapping):

    """
    Local memory mapping.
    The memory space is present in local ctypes space.
    """

    def __init__(self, address, start, end, permissions, offset,
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
        # DEBUG TODO byte or ubyte
        self._local_mmap = (ctypes.c_ubyte * len(self)).from_address(int(address))
        self._address = ctypes.addressof(self._local_mmap)
        self._bytebuffer = None

    def _vtop(self, vaddr):
        ret = vaddr - self.start + self._address
        if ret < self._address or ret > (self._address + len(self)):
            raise ValueError('0x%0.8x/0x%0.8x is not a valid vaddr for me: %s' % (vaddr, ret, self))
        return ret

    def mmap(self):
        return self

    def read_word(self, vaddr):
        """Address have to be aligned!"""
        laddr = self._vtop(vaddr)
        # word = self._target_platform.get_word_type().from_address(long(laddr)).value
        word = self._ctypes.c_ulong.from_address(long(laddr)).value
        # is non-aligned a pb ?, indianess is at risk
        return word

    def _read_bytes(self, vaddr, size):
        laddr = self._vtop(vaddr)
        #data = b''.join([ struct.pack('B',x) for x in self.readArray( vaddr, ctypes.c_ubyte, size) ] )
        data = ctypes.string_at(laddr, size)  # real 0.5 % perf
        return data
    read_bytes = _read_bytes

    def read_buffer_bytes(self, vaddr, size):
        laddr = vaddr - self.start
        return self._bytebuffer[laddr:laddr + size]

    def read_struct(self, vaddr, struct):
        laddr = self._vtop(vaddr)
        struct = struct.from_address(int(laddr))
        #struct = struct.from_buffer_copy(struct.from_address(int(laddr)))
        struct._orig_address_ = vaddr
        return struct

    def read_array(self, vaddr, basetype, count):
        laddr = self._vtop(vaddr)
        array = (basetype * count).from_address(int(laddr))
        return array

    def get_byte_buffer(self):
        if self._bytebuffer is None:
            self._bytebuffer = self.read_bytes(self.start, len(self))
            self.read_bytes = self.read_buffer_bytes
        return self._bytebuffer

    def init_byte_buffer(self, data=None):
        self._bytebuffer = data

    def __getstate__(self):
        d = dict(self.__dict__)
        del d['_local_mmap']
        del d['_bytebuffer']
        return d

    @classmethod
    def fromAddress(cls, memoryMapping, content_address):
        el = cls(content_address, memoryMapping.start, memoryMapping.end,
                 memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                 memoryMapping.inode, memoryMapping.pathname)
        if memoryMapping._ctypes:
            el.set_ctypes(memoryMapping._ctypes)
        return el

    @classmethod
    def fromBytebuffer(cls, memoryMapping, content):
        content_array = utils.bytes2array(content, ctypes.c_ubyte)
        content_address = ctypes.addressof(content_array)
        el = cls(content_address, memoryMapping.start, memoryMapping.end,
                 memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                 memoryMapping.inode, memoryMapping.pathname)
        if memoryMapping._ctypes:
            el.set_ctypes(memoryMapping._ctypes)
        el.content_array_save_me_from_gc = content_array
        return el


class MemoryDumpMemoryMapping(AMemoryMapping):

    """
    A memoryMapping wrapper around a memory file dump.
    A lazy loading is done for that file, to quick load MM, withouth copying content

    :param offset the offset in the memory dump file from which the start offset will be mapped for end-start bytes
    :param preload mmap the memory dump at init ( default)
    """

    def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0,
                 major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP', preload=False):
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
        self._memdump = memdump
        self._base = None
        if preload:
            self._mmap()

    def use_byte_buffer(self):
        # toddo use bitstring
        self._mmap().get_byte_buffer()  # XXX FIXME buggy
        # force readBytes update
        self.read_bytes = self._base.read_bytes

    def get_byte_buffer(self):
        return self._mmap().get_byte_buffer()

    def is_mmaped(self):
        return not (self._base is None)

    def mmap(self):
        """ mmap-ed access gives a 20% perf increase on by tests """
        if not self.is_mmaped():
            self._mmap()
        return self._base

    def unmmap(self):
        raise NotImplementedError

    def rebase(self, new_start_address):
        super(MemoryDumpMemoryMapping, self).rebase(new_start_address)
        if self.is_mmaped():
            self._base.rebase(new_start_address)

    def _mmap(self):
        """ protected api """
        # mmap.mmap has a full bytebuffer API, so we can use it as is for bytebuffer.
        # we have to get a ctypes pointer-able instance to make our ctypes structure read efficient.
        # sad we can't have a bytebuffer from that same raw memspace
        # we do not keep the bytebuffer in memory, because it's a lost of space
        # in most cases.
        if self._base is None:
            if hasattr(self._memdump, 'fileno'):  # normal file.
                # XXX that is the most fucked up, non-portable fuck I ever
                # wrote.
                if MMAP_HACK_ACTIVE:
                    log.debug('Using MMAP_HACK: %s' % self)
                    # if self.pathname.startswith('/usr/lib'):
                    #    raise Exception
                    self._local_mmap_bytebuffer = mmap.mmap(
                        self._memdump.fileno(),
                        self.end - self.start,
                        access=mmap.ACCESS_READ)
                    self._memdump.close()
                    self._memdump = None
                    # yeap, that right, I'm stealing the pointer value. DEAL WITH IT.
                    # this is a local memory hack, so
                    heapmap = struct.unpack('L', ctypes.c_ulong.from_address(
                        id(self._local_mmap_bytebuffer) + 2 * (ctypes.sizeof(ctypes.c_ulong))))[0]
                    self._local_mmap_content = (ctypes.c_ubyte * (self.end - self.start)).from_address(int(heapmap))
                else:  # fallback with no creepy hacks
                    log.warning('MemoryHandler Mapping content mmap-ed() (double copy of %s) : %s',
                        self._memdump.__class__, self)
                    # we have the bytes
                    local_mmap_bytebuffer = mmap.mmap(
                        self._memdump.fileno(),
                        self.end - self.start,
                        access=mmap.ACCESS_READ)
                    self._memdump.close()
                    # we need an ctypes
                    self._local_mmap_content = utils.bytes2array(local_mmap_bytebuffer, ctypes.c_ubyte)
            else:  # dumpfile, file inside targz ... any read() API really
                print(self.__class__)
                self._local_mmap_content = utils.bytes2array(self._memdump.read(), ctypes.c_ubyte)
                self._memdump.close()
                log.warning('MemoryHandler Mapping content copied to ctypes array : %s', self)
            # make that _base
            self._base = LocalMemoryMapping.fromAddress(self, ctypes.addressof(self._local_mmap_content))
            log.debug('%s done.' % self.__class__)
        # redirect function calls
        self.read_word = self._base.read_word
        self.read_array = self._base.read_array
        self.read_bytes = self._base.read_bytes
        self.read_struct = self._base.read_struct
        return self._base

    def _read_word(self, vaddr):
        return self._mmap().read_word(vaddr)

    def _read_bytes(self, vaddr, size):
        return self._mmap().read_bytes(vaddr, size)

    def _read_struct(self, vaddr, structType):
        return self._mmap().read_struct(vaddr, structType)

    def _read_array(self, vaddr, basetype, count):
        return self._mmap().read_array(vaddr, basetype, count)

    # set the default
    read_word = _read_word
    read_array = _read_array
    read_bytes = _read_bytes
    read_struct = _read_struct

    def __getstate__(self):
        d = dict(self.__dict__)
        if hasattr(self, '_memdump.name'):
            d['_memdump_filename'] = self._memdump.name
        d['_memdump'] = None
        d['_local_mmap'] = None
        d['_local_mmap_content'] = None
        d['_base'] = None
        d['_process'] = None
        return d

    @classmethod
    def fromFile(cls, memoryMapping, aFile):
        """
            aFile must be able to read().
        """
        return cls(aFile, memoryMapping.start, memoryMapping.end,
                   memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                   memoryMapping.inode, memoryMapping.pathname)


class FileBackedMemoryMapping(MemoryDumpMemoryMapping):

    """
        Don't mmap the memoryMap. use the file on disk to read data.
    """

    def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0,
                 major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
        MemoryDumpMemoryMapping.__init__(
            self,
            memdump,
            start,
            end,
            permissions,
            offset,
            major_device,
            minor_device,
            inode,
            pathname,
            preload=False)
        self._local_mmap = LazyMmap(self._memdump)
        log.debug('FileBackedMemoryMapping created')
        return

    def _mmap(self):
        """ returns self to force super() to read through us    """
        return self

    def _vtop(self, vaddr):
        ret = vaddr - self.start
        if ret < 0 or ret > len(self):
            raise ValueError(
                '%x/%x is not a valid vaddr for me' %
                (vaddr, ret))
        return ret

    def read_bytes(self, vaddr, size):
        laddr = self._vtop(vaddr)
        size = ctypes.sizeof((ctypes.c_ubyte * size))
        data = b''.join([struct.pack('B', x)
                         for x in self._local_mmap[laddr:laddr + size]])
        return data

    def read_struct(self, vaddr, structType):
        laddr = self._vtop(vaddr)
        size = ctypes.sizeof(structType)
        # YES you DO need to have a copy, otherwise you finish with a allocated
        # struct in a read-only mmaped file. Not good if you want to changed members pointers after that.
        # but at the same time, why would you want to CHANGE anything ?
        struct = structType.from_buffer_copy(
            self._local_mmap[
                laddr:laddr +
                size],
            0)
        struct._orig_address_ = vaddr
        return struct

    def read_word(self, vaddr):
        """Address have to be aligned!"""
        laddr = self._vtop(vaddr)
        size = self._ctypes.sizeof(self._ctypes.c_ulong)
        word = self._ctypes.c_ulong.from_buffer_copy(self._local_mmap[laddr:laddr + size], 0).value
        # is non-aligned a pb ?
        return word

    def read_array(self, address, basetype, count):
        laddr = self._vtop(address)
        size = ctypes.sizeof((basetype * count))
        array = (
            basetype *
            count).from_buffer_copy(
            self._local_mmap[
                laddr:laddr +
                size],
            0)
        return array

    @classmethod
    def fromFile(cls, memoryMapping, memdump):
        """
            Transform a MemoryMapping to a file-backed MemoryMapping using FileBackedMemoryMapping.

            memoryMapping is the MemoryMapping instance.
            memdump is used as memory_mapping content.

        """
        return cls(memdump, memoryMapping.start, memoryMapping.end,
                   memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                   memoryMapping.inode, memoryMapping.pathname)


class FilenameBackedMemoryMapping(MemoryDumpMemoryMapping):

    """
        Don't mmap the memoryMap. use the file name on disk to read data.
    """

    def __init__(self, memdumpname, start, end, permissions='rwx-', offset=0x0,
                 major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
        MemoryDumpMemoryMapping.__init__(self, None, start, end, permissions, offset,
                                         major_device, minor_device, inode, pathname, preload=False)
        self._memdumpname = memdumpname
        assert isinstance(self._memdumpname, str)
        return

    def _mmap(self):
        #import code
        # code.interact(local=locals())
        self._memdump = open(self._memdumpname, 'rb')
        # memdump is closed by super()
        return MemoryDumpMemoryMapping._mmap(self)

    def reset(self):
        """
        Allows for this lazy-loading mapping wrapper to return
        to a non-loaded state, closing opened file descriptors.
        :return:
        """
        self._local_mmap_content = None
        if hasattr(self, '_local_mmap_bytebuffer'):
            if self._local_mmap_bytebuffer:
                self._local_mmap_bytebuffer.close()
                self._local_mmap_bytebuffer = None
        self._memdump = None
        self._base = None
        self.read_word = self._read_word
        self.read_array = self._read_array
        self.read_bytes = self._read_bytes
        self.read_struct = self._read_struct


class LazyMmap:

    """
    lazy mmap no memory.
    """

    def __init__(self, memdump):
        i = memdump.tell()
        try:
            memdump.seek(2 ** 64)
        except OverflowError:
            memdump.seek(os.fstat(memdump.fileno()).st_size)
        self.size = memdump.tell()
        self.memdump_name = memdump.name
        memdump.seek(i)
        memdump.close()

    def __len__(self):
        return self.size

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start
            size = key.stop - key.start
        elif isinstance(key, int):
            start = key
            size = 1
        else:
            raise ValueError('bad index type')
        return self._get(start, size)

    def _get(self, offset, size):
        memdump = open(self.memdump_name, 'rb')
        memdump.seek(offset)
        me = utils.bytes2array(memdump.read(size), ctypes.c_ubyte)
        memdump.close()
        return me


class MMapProcessMapping(base.AMemoryMapping):
    """Process memory mapping using 1 file for all mappings """

    def __init__(self, mmap_content, start, end, permissions='r--',
                 offset=0, major_device=0, minor_device=0, inode=0, pathname=''):
        """mmap_content should be """
        base.AMemoryMapping.__init__(self, start, end, permissions, offset,
                                     major_device, minor_device, inode, pathname)
        self._backend = mmap_content
        self.offset = offset

    def read_word(self, addr):
        ws = self._ctypes.sizeof(self._ctypes.c_void_p)
        self._backend.seek(self.offset + addr - self.start, 0)
        data = self._backend.read(ws)
        if ws == 4:
            return struct.unpack('I', data)[0]
        elif ws == 8:
            return struct.unpack('Q', data)[0]

    def read_bytes(self, addr, size):
        self._backend.seek(self.offset + addr - self.start, 0)
        return self._backend.read(size)

    def read_struct(self, addr, struct):
        size = self._ctypes.sizeof(struct)
        self._backend.seek(self.offset + addr - self.start, 0)
        instance = struct.from_buffer_copy(self._backend.read(size))
        instance._orig_address_ = addr
        return instance

    def read_array(self, addr, basetype, count):
        size = self._ctypes.sizeof(basetype * count)
        self._backend.seek(self.offset + addr - self.start, 0)
        array = (basetype *count).from_buffer_copy(self._backend.read(size))
        return array

    def reset(self):
        pass
