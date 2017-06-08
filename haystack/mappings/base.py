#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Provides basic memory _memory_handler helpers.

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

# haystack
from haystack import utils
from haystack import model
from haystack.abc import interfaces
from haystack.allocators import heapwalker

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('memorybase')


class AMemoryMapping(interfaces.IMemoryMapping):

    """
    Just the metadata.

        Attributes:
         - start (int): first byte address
         - end (int): last byte address + 1
         - permissions (str)
         - offset (int): for file, offset in bytes from the file start
         - major_device / minor_device (int): major / minor device number
         - inode (int)
         - pathname (str)
         - _process: weak reference to the process

        Operations:
         - "address in mapping" checks the address is in the mapping.
         - "search(somestring)" returns the offsets of "somestring" in the mapping
         - "mmap" mmap the MemoryMap to local address space
         - "readWord()": read a memory word, from local mmap-ed memory if mmap-ed
         - "readBytes()": read some bytes, from local mmap-ed memory if mmap-ed
         - "readStruct()": read a structure, from local mmap-ed memory if mmap-ed
         - "readArray()": read an array, from local mmap-ed memory if mmap-ed
         - "readCString()": read a C string, from local mmap-ed memory if mmap-ed
         - "str(mapping)" create one string describing the mapping
         - "repr(mapping)" create a string representation of the mapping,
             useful in list contexts
    """

    def __init__(self, start, end, permissions, offset,
                 major_device, minor_device, inode, pathname):
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = str(pathname)  # fix None
        self._is_heap = False
        self._is_heap_addr = None
        self._ctypes = None
        self._utils = None

    def set_ctypes(self, _ctypes):
        self._ctypes = _ctypes
        self._utils = utils.Utils(_ctypes)

    def __contains__(self, address):
        return self.start <= address < self.end

    def __str__(self):
        start = '0x%0.8x' % self.start
        end = '0x%0.8x' % self.end
        size = 'size:0x%0.8x' % (self.end-self.start)
        offset = 'offset:0x%0.8x' % self.offset
        device = '%0.2x:%0.2x' % (self.major_device, self.minor_device)
        inode = 'inode:%0.7d' % self.inode
        text = ' '.join([start, end, self.permissions, size, offset, device, inode, str(self.pathname)])
        return text

    __repr__ = __str__

    def __len__(self):
        return int(self.end - self.start)

    def __gt__(self, o):
        return self.start > o.start

    def search(self, bytestr):
        bytestr_len = len(bytestr)
        buf_len = 64 * 1024
        if buf_len < bytestr_len:
            buf_len = bytestr_len
        remaining = self.end - self.start
        covered = self.start
        while remaining >= bytestr_len:
            if remaining > buf_len:
                requested = buf_len
            else:
                requested = remaining
            data = self.read_bytes(covered, requested)
            if data == "":
                break
            offset = data.find(bytestr)
            if offset == -1:
                skip = requested - bytestr_len + 1
            else:
                yield (covered + offset)
                skip = offset + bytestr_len
            covered += skip
            remaining -= skip
        return

    def read_cstring(self, address, max_size, chunk_length=256):
        """ Read character up to max_size until a \x00 byte is found """
        string = []
        size = 0
        truncated = False
        while True:
            done = False
            data = self.read_bytes(address, chunk_length)
            if '\0' in data:
                done = True
                data = data[:data.index('\0')]
            if max_size <= size + chunk_length:
                data = data[:(max_size - size)]
                string.append(data)
                truncated = True
                break
            string.append(data)
            if done:
                break
            size += chunk_length
            address += chunk_length
        return ''.join(string), truncated

    def _vtop(self, vaddr):
        ret = vaddr - self.start
        if ret < 0 or ret > len(self):
            raise ValueError(
                '%x/%x is not a valid vaddr for me' %
                (vaddr, ret))
        return ret

    def _ptov(self, paddr):
        pstart = self._vtop(self.start)
        vaddr = paddr - pstart
        return vaddr

    # ---- to implement if needed
    def read_word(self, address):
        raise NotImplementedError(self)

    def read_bytes(self, address, size):
        raise NotImplementedError(self)

    def read_struct(self, address, struct):
        raise NotImplementedError(self)

    def read_array(self, address, basetype, count):
        raise NotImplementedError(self)

    def rebase(self, new_start_address):
        log.debug("rebasing 0x%0.8x -> 0x%0.8x", self.start, new_start_address)
        end = new_start_address + len(self)
        self.start = new_start_address
        self.end = end


class MemoryHandler(interfaces.IMemoryHandler, interfaces.IMemoryCache):
    """
    Handler for the concept of process memory.

    Parse a process memory _memory_handler from a storage concept,
    then identify its ITargetPlatform characteristics
    and produce an IMemoryHandler for this process memory dump """

    def __init__(self, mapping_list, _target, name):
        """Set the list of IMemoryMapping and the ITargetPlatform

        :param mapping_list: list of IMemoryMapping
        :param _target: the ITargetPlatform
        :return: IMemoryHandler, self
        :rtype: IMemoryHandler
        """
        if not isinstance(mapping_list, list):
            raise TypeError('Please feed me a list of IMemoryMapping')
        if not isinstance(_target, interfaces.ITargetPlatform):
            raise TypeError('Please feed me a ITargetPlatform')
        self._mappings = sorted(mapping_list)
        self._target = _target
        for m in mapping_list:
            m.set_ctypes(self._target.get_target_ctypes())
        self._utils = self._target.get_target_ctypes_utils()
        self.__name = name
        # book register to keep references to ctypes memory buffers
        self.__book = _book()
        self.__user_model = model.Model(self._target.get_target_ctypes())
        self.__internal_model = model.Model(self._target.get_target_ctypes())
        # FIXME reduce open files.
        self.__required_maps = []
        # finish initialization
        self._heap_finder = None
        self.__optim_get_mapping_for_address()
        self.__context = None

    def get_name(self):
        """Returns the name of the process memory dump we are analysing"""
        return self.__name

    def get_target_platform(self):
        """Returns the ITargetPlatform for that process memory."""
        return self._target

    def get_heap_finder(self):
        """Returns the IHeapFinder for that process memory."""
        if self._heap_finder is None:
            self._heap_finder = heapwalker.make_heap_finder(self)
        return self._heap_finder

    def get_model(self):
        """Returns the Model cache."""
        return self.__user_model

    # FIXME incorrect API
    def _get_mapping(self, pathname):
        mmap = None
        if len(self._mappings) >= 1:
            mmap = [m for m in self._mappings if m.pathname == pathname]
        if len(mmap) < 1:
            raise IndexError('No mmap of pathname %s' % pathname)
        return mmap

    def get_mappings(self):
        return list(self._mappings)

    def reset_mappings(self):
        """
        Temporarly closes all file used by this handler.
        :return:
        """
        log.debug('reset_mappings')
        # clean the book
        self.__book = _book()
        # reset the mappings
        for m in self.get_mappings():
            m.reset()

    def __optim_get_mapping_for_address(self):
        self.__optim_get_mapping_for_address_cache = dict()
        for m in self.get_mappings():
            for i in range(m.start, m.end, 0x1000):
                self.__optim_get_mapping_for_address_cache[i] = m
        return

    def get_mapping_for_address(self, vaddr):
        # TODO: optimization. 127s out of 288s = 40%
        assert isinstance(vaddr, long) or isinstance(vaddr, int)
        # check 4 Mo boundaries
        _boundary_addr = (vaddr >> 12) << 12
        if _boundary_addr in self.__optim_get_mapping_for_address_cache:
            return self.__optim_get_mapping_for_address_cache[_boundary_addr]
        return False

    # reverse helper
    def get_reverse_context(self):
        from haystack.reverse import context
        if self.__context is None:
            # try to cache load

            # otherwise, create an empty one.
            self.__context = context.ProcessContext(self)
        return self.__context

    def is_valid_address(self, obj, structType=None):  # FIXME is valid pointer
        """
        :param obj: the obj to evaluate.
        :param structType: the object's type, so the size could be taken in consideration.

        Returns False if the object address is NULL.
        Returns False if the object address is not in a mapping.

        Returns the mapping in which the object stands otherwise.
        """
        # check for null pointers
        addr = self._utils.get_pointee_address(obj)
        if addr == 0:
            return False
        return self.is_valid_address_value(addr, structType)

    def is_valid_address_value(self, addr, structType=None):
        """
        :param addr: the address to evaluate.
        :param structType: the object's type, so the size could be taken in consideration.

        Returns False if the object address is NULL.
        Returns False if the object address is not in a mapping.
        Returns False if the object overflows the mapping.

        Returns the mapping in which the address stands otherwise.
        """
        my_ctypes = self._target.get_target_ctypes()
        m = self.get_mapping_for_address(addr)
        log.debug('is_valid_address_value = %x %s' % (addr, m))
        if m:
            if structType is not None:
                s = my_ctypes.sizeof(structType)
                if (addr + s) < m.start or (addr + s) > m.end:
                    return False
            return m
        return False

    def __contains__(self, vaddr):
        for m in self._mappings:
            if vaddr in m:
                return True
        return False

    def __len__(self):
        return len(self._mappings)

    def __getitem__(self, i):
        return self._mappings[i]

    def __setitem__(self, i, val):
        raise NotImplementedError()

    def __iter__(self):
        return iter(self._mappings)

    def __str__(self):
        return "<MemoryHandler for %s with %d mappings>" % (self.get_name(), len(self.get_mappings()))

    def reset(self):
        """Clean the book"""
        self.__book.refs = dict()

    def getRefs(self):
        """Lists all references to already loaded structs. Useful for debug"""
        return self.__book.refs.items()

    def printRefs(self):
        """Prints all references to already loaded structs. Useful for debug"""
        l = [(typ, obj, addr)
             for ((typ, addr), obj) in self.__book.refs.items()]
        for i in l:
            print(l)

    def printRefsLite(self):
        """Prints all references to already loaded structs. Useful for debug"""
        l = [(typ, addr) for ((typ, addr), obj) in self.__book.refs.items()]
        for i in l:
            print(l)

    def hasRef(self, typ, origAddr):
        """Check if this type has already been loaded at this address"""
        return (typ, origAddr) in self.__book.refs

    def getRef(self, typ, origAddr):
        """Returns the reference to the type previously loaded at this address"""
        if (typ, origAddr) in self.__book.refs:
            return self.__book.getRef(typ, origAddr)
        return None

    def getRefByAddr(self, addr):
        ret = []
        for (typ, origAddr) in self.__book.refs.keys():
            if origAddr == addr:
                ret.append((typ, origAddr, self.__book.refs[(typ, origAddr)]))
        return ret

    def keepRef(self, obj, typ=None, origAddr=None):
        """Keeps a reference for an object of a specific type loaded from a specific
        address.

        Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object,
           they might be transient (if obj == somepointer.contents)."""
        # TODO, memory leak for different objects of same size, overlapping
        # struct.
        if (typ, origAddr) in self.__book.refs:
            # ADDRESS already in refs
            if origAddr is None:
                origAddr = 'None'
            else:
                origAddr = hex(origAddr)
            if typ is not None:
                log.debug('ignore keepRef - references already in cache %s/%s', typ, origAddr)
            return
        # there is no pre-existing typ().from_address(origAddr)
        self.__book.addRef(obj, typ, origAddr)
        return

    def delRef(self, typ, origAddr):
        """Forget about a Ref."""
        if (typ, origAddr) in self.__book.refs:
            self.__book.delRef(typ, origAddr)
        return

    def rebase_mapping(self, user_mapping, new_start_address):
        """
        Rebase a mapping in a new address space.
        :param user_mapping:
        :param new_start_address:
        :return:
        """
        if user_mapping not in self._mappings:
            raise ValueError("User mapping not found")
        log.debug("rebase_mapping 0x%0.8x -> 0x%0.8x", user_mapping.start, new_start_address)
        user_mapping = self._mappings[self._mappings.index(user_mapping)]
        user_mapping.rebase(new_start_address)
        # end = new_start_address + len(user_mapping)
        # user_mapping.start = new_start_address
        # user_mapping.end = end
        self._mappings.sort()
        # reset the caches too
        self.__optim_get_mapping_for_address()
        return user_mapping


class _book(object):

    """The book registers all registered ctypes modules and keeps
    some pointer refs to buffers allocated in memory _memory_handler.

    # see also ctypes._pointer_type_cache , _reset_cache()
    """

    def __init__(self):
        self.refs = dict()
        pass

    def addRef(self, obj, typ, addr):
        self.refs[(typ, addr)] = obj

    def getRef(self, typ, addr):
        if len(self.refs) > 35000:
            log.warning('the book is full, you should haystack.model.reset()')
        return self.refs[(typ, addr)]

    def delRef(self, typ, addr):
        del self.refs[(typ, addr)]
