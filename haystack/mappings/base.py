#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Provides basic memory mappings helpers.

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
Its intended to be retrofittable with ptrace's memory mappings.
"""

import logging

# haystack
from haystack import utils
from haystack import config

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('base')

class MemoryMapping:
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
    def __init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        self.config = None
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = str(pathname) #fix None

    def init_config(self, config):
        self.config = config
        return

    def __contains__(self, address):
            return self.start <= address < self.end

    def __str__(self):
        text = ' '.join([utils.formatAddress( self.start), utils.formatAddress(self.end), self.permissions,
                     '0x%0.8x'%(self.offset), '%0.2x:%0.2x'%(self.major_device, self.minor_device), '%0.7d'%(self.inode), str(self.pathname)])
        return text

    __repr__ = __str__

    def __len__(self):
        return int(self.end - self.start)
    
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
            data = self.readBytes(covered, requested)
            if data == "":
                break
            offset = data.find(bytestr)
            if (offset == -1):
                skip = requested - bytestr_len + 1
            else:
                yield (covered + offset)
                skip = offset + bytestr_len
            covered += skip
            remaining -= skip
        return 
    def readCString(self, address, max_size, chunk_length=256):
        ''' identic to process.readCString '''
        string = []
        size = 0
        truncated = False
        while True:
            done = False
            data = self.readBytes(address, chunk_length)
            if '\0' in data:
                done = True
                data = data[:data.index('\0')]
            if max_size <= size+chunk_length:
                data = data[:(max_size-size)]
                string.append(data)
                truncated = True
                break
            string.append(data)
            if done:
                break
            size += chunk_length
            address += chunk_length
        return ''.join(string), truncated

    def vtop(self, vaddr):
        ret = vaddr - self.start
        if ret<0 or ret>len(self):
            raise ValueError('%x/%x is not a valid vaddr for me'%(vaddr,ret))
        return ret

    def ptov(self, paddr):
        pstart = self.vtop(self.start)
        vaddr = paddr-pstart
        return vaddr
    
    # ---- to implement if needed
    def readWord(self, address):
        raise NotImplementedError(self)
    def readBytes(self, address, size):
        raise NotImplementedError(self)
    def readStruct(self, address, struct):
        raise NotImplementedError(self)
    def readArray(self, address, basetype, count):
        raise NotImplementedError(self)



class Mappings:
    """List of memory mappings for one process"""
    def __init__(self, lst, name='noname'):
        self.heaps = None
        if lst is None:
            self.mappings = []
        elif type(lst) != list:
            raise TypeError('Please feed me a list')
        else:
            self.mappings = list(lst)
        self._target_system = None
        self.config = None #
        self.name = name
        # book register to keep references to ctypes memory buffers
        self.__book = _book()
        # set the word size in this config.
        self.__wordsize = None
        self.__required_maps = []
        #self._init_word_size()
    
    def get_context(self, addr):
        """Returns the haystack.reverse.context.ReverserContext of this dump.
        """
        mmap = self.getMmapForAddr(addr)
        if not mmap:
            raise ValueError
        if hasattr(mmap, '_context'):
            #print '** _context exists'
            return mmap._context        
        if mmap not in self.getHeaps(): # addr is not a heap addr, 
            found = False
            # or its in a child heap ( win7)
            for h in self.getHeaps():
                if hasattr(h, '_children'):
                    if mmap in h._children:
                        found = True
                        mmap = h
                        break
            if not found:
                raise ValueError
        # we found the heap mmap or its parent
        from haystack.reverse import context
        try:
            ctx = context.ReverserContext.cacheLoad(self)
            #print '** CACHELOADED'
        except IOError,e:
            ctx = context.ReverserContext(self, mmap)    
            #print '** newly loaded '
        # cache it
        mmap._context = ctx
        return ctx
    
    def get_user_allocations(self, heap, filterInUse=True):
        """changed when the dump is loaded"""
        # set by dump_loader. DO NOT FIX
        raise NotImplementedError
        # FIXME why is this in dump_loader
        #if self.mappings.get_target_system() == 'win32':
        #    self.mappings.search_win_heaps() # mmmh neeeh...
        #    from haystack.structures.win32 import win7heapwalker
        #    self.mappings.get_user_allocations = win7heapwalker.get_user_allocations
        #else: # linux/libc
        #    from haystack.structures.libc import libcheapwalker
        #    self.mappings.get_user_allocations = libcheapwalker.get_user_allocations

    def getMmap(self, pathname):
        mmap = None
        if len(self.mappings) >= 1:
            mmap = [m for m in self.mappings if m.pathname == pathname]
        if len(mmap) < 1:
            raise IndexError('No mmap of pathname %s'%(pathname))
        return mmap

    def getMmapForAddr(self, vaddr):
        for m in self.mappings:
            if vaddr in m:
                return m
        return False

    def getHeap(self):
        #if len(self.mappings) == 0:
        #        import code
        #        code.interact(local=locals())
        #log.debug('heaps: %s'%(self.heaps))
        #import code        
        #code.interact(local=locals())
        return self.getHeaps()[0]

    def getHeaps(self):
        # This does not really exists on win32.
        # getHeaps() will be more appropriate...
        # this fn is used onlly in reverse/*
        if self.heaps is None:
            if self.get_target_system() == 'linux':
                self.heaps = self.search_nux_heaps()
            else:
                self.heaps = self.search_win_heaps()
        return self.heaps

    def getStack(self):
        stack = self.getMmap('[stack]')[0] 
        return stack

    def append(self, m):
        self.mappings.append(m)
        if self.config is not None:
            m.config = self.config

    def search_nux_heaps(self):
        # TODO move in haystack.reverse.heapwalker
        from haystack.structures.libc import libcheapwalker 
        heaps = self.getMmap('[heap]')
        for mapping in self.getMmap('None'):
            if libcheapwalker.is_heap(self, mapping):
                heaps.append(mapping)
                log.debug('%s is a Heap'%(mapping))
            else:
                log.debug('%s is NOT a Heap'%(mapping))
        # order by ProcessHeapsListIndex
        #heaps.sort(key=lambda m: win7heapwalker.readHeap(m).ProcessHeapsListIndex)
        return heaps

    def search_win_heaps(self):
        # TODO move in haystack.reverse.heapwalker
        # FIXME, why do we keep a ref to children mmapping ?
        log.debug('search_win_heaps - START')
        from haystack.structures.win32 import win7heapwalker # FIXME win7, winxp...
        heaps = list()
        for mapping in self.mappings:
            if win7heapwalker.is_heap(self, mapping):
                heaps.append(mapping)
                log.debug('%s is a Heap'%(mapping))
                mapping._children = win7heapwalker.Win7HeapWalker(self, mapping, 0).get_heap_children_mmaps()
        # order by ProcessHeapsListIndex
        heaps.sort(key=lambda m: win7heapwalker.readHeap(m).ProcessHeapsListIndex)
        log.debug('search_win_heaps - END')
        return heaps
    
    def get_target_system(self):
        if self._target_system is not None:
            return self._target_system
        self._target_system = 'linux'
        for l in [m.pathname for m in self.mappings]:
            if l is not None and '\\System32\\' in l:
                log.debug('Found a windows executable dump')
                self._target_system = 'win32'
                break
        return self._target_system

    def init_config(self):
        if self.__wordsize is not None:
            return self.__wordsize
        elif self.get_target_system() == 'win32':
            self._process_machine_arch_pe()
        elif self.get_target_system() == 'linux':
            self._process_machine_arch_elf()
        else:
            raise NotImplementedError('MACHINE is %s'%(x.e_machine))
        self._reset_config()
        self.__wordsize = self.config.get_word_size()
        return
    
    def _reset_config(self):
        # This is where the config is set for all maps.
        for m in self.mappings:
            m.config = self.config
        return
    
    def _process_machine_arch_pe(self):
        import pefile
        # get the maps with read-only data
        # find the executable image and get the PE header
        pe = None
        m = [_m for _m in self.mappings if 'r--' in _m.permissions][0]
        for m in self.mappings:
            if m.permissions != 'r--':
                continue
            try:
                pe = pefile.PE(data=m.getByteBuffer(), fast_load=True)
                # only get the dirst one that works
                break
            except pefile.PEFormatError as e:
                pass
        self.__required_maps.append(m)
        machine = pe.FILE_HEADER.Machine
        arch = pe.OPTIONAL_HEADER.Magic
        if arch == 0x10b:
            self.config = config.make_config_win32()
        elif arch == 0x20b:
            self.config = config.make_config_win64()
        else:
            raise NotImplementedError('MACHINE is %s'%(x.e_machine))
        return 

    def _process_machine_arch_elf(self):
        import ctypes
        from haystack.structures.libc.ctypes_elf import struct_Elf_Ehdr
        # find an executable image and get the ELF header
        for m in self.mappings:
            if 'r-xp' not in m.permissions:
                continue
            head = m.readBytes(m.start, ctypes.sizeof(struct_Elf_Ehdr))
            x = struct_Elf_Ehdr.from_buffer_copy(head)
            self.__required_maps.append(m)
            log.debug('MACHINE:%s pathname:%s'%(x.e_machine, m.pathname))
            if x.e_machine == 3:
                self.config = config.make_config_linux32()
                return
            elif x.e_machine == 62:
                self.config = config.make_config_linux64()
                return
            else:
                continue
        raise NotImplementedError('MACHINE has not been found.')

    def get_required_maps(self):
        return list(self.__required_maps)
    
    def is_valid_address(self, obj, structType=None): # FIXME is valid pointer
        """ 
        :param obj: the obj to evaluate.
        :param structType: the object's type, so the size could be taken in consideration.

        Returns False if the object address is NULL.
        Returns False if the object address is not in a mapping.

        Returns the mapping in which the object stands otherwise.
        """
        # check for null pointers
        addr = utils.get_pointee_address(obj)
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
        import ctypes
        m = self.getMmapForAddr(addr)
        log.debug('is_valid_address_value = %x %s'%(addr, m))
        if m:
            if (structType is not None):
                s = ctypes.sizeof(structType)
                if (addr+s) < m.start or (addr+s) > m.end:
                    return False
            return m
        return False
        
    def __contains__(self, vaddr):
        for m in self.mappings:
            if vaddr in m:
                return True
        return False

    def __len__(self):
        return len(self.mappings)
    def __getitem__(self, i):
        return self.mappings[i]
    def __setitem__(self,i,val):
        raise NotImplementedError()
    def __iter__(self):
        return iter(self.mappings)

            
    def reset(self):
        """Clean the book"""
        self.__book.refs = dict()

    def getRefs(self):
        """Lists all references to already loaded structs. Useful for debug"""
        return self.__book.refs.items()

    def printRefs(self):
        """Prints all references to already loaded structs. Useful for debug"""
        l=[(typ,obj,addr) for ((typ,addr),obj) in self.__book.refs.items()]
        for i in l:
            print(l)

    def printRefsLite(self):
        """Prints all references to already loaded structs. Useful for debug"""
        l=[(typ,addr) for ((typ,addr),obj) in self.__book.refs.items()]
        for i in l:
            print(l)

    def hasRef(self, typ,origAddr):
        """Check if this type has already been loaded at this address"""
        return (typ,origAddr) in self.__book.refs

    def getRef(self, typ,origAddr):
        """Returns the reference to the type previously loaded at this address"""
        if (typ,origAddr) in self.__book.refs:
            return self.__book.getRef(typ,origAddr)
        return None

    def getRefByAddr(self, addr):
        ret=[]
        for (typ,origAddr) in self.__book.refs.keys():
            if origAddr == addr:
                ret.append( (typ, origAddr, self.__book.refs[(typ, origAddr)] ) )
        return ret

    def keepRef(self, obj,typ=None,origAddr=None):
        """Keeps a reference for an object of a specific type loaded from a specific
        address.
        
        Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object, 
           they might be transient (if obj == somepointer.contents)."""
        # TODO, memory leak for different objects of same size, overlapping struct.
        if (typ,origAddr) in self.__book.refs:
            # ADDRESS already in refs
            if origAddr is None:
                origAddr = 'None'
            else:
                origAddr = hex(origAddr)
            if typ is not None:
                log.debug('ignore keepRef - references already in cache %s/%s'%(typ,origAddr))
            return
        # there is no pre-existing typ().from_address(origAddr)
        self.__book.addRef(obj,typ,origAddr)
        return

    def delRef(self, typ, origAddr):
        """Forget about a Ref."""
        if (typ,origAddr) in self.__book.refs:
            self.__book.delRef(typ,origAddr)
        return

class _book(object):
    """The book registers all registered ctypes modules and keeps 
    some pointer refs to buffers allocated in memory mappings.
    
    # see also ctypes._pointer_type_cache , _reset_cache()
    """

    def __init__(self):
        self.refs = dict()
        pass
    def addRef(self,obj, typ, addr):
        self.refs[(typ,addr)]=obj
    def getRef(self,typ,addr):
        if len(self.refs) > 35000:
            log.warning('the book is full, you should haystack.model.reset()')
        return self.refs[(typ,addr)]
    def delRef(self,typ,addr):
        del self.refs[(typ,addr)]



