#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''Provide several memory mapping wrappers to handle different situations.

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
'''

import os
import logging
import re
import ctypes
import struct
import mmap
from weakref import ref

# haystack
from haystack.dbg import openProc, ProcError, ProcessError, HAS_PROC
from haystack import types
from haystack import utils
from haystack import config

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('memory_mapping')

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

class ProcessMemoryMapping(MemoryMapping):
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
    def __init__(self, process, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._process = ref(process)
        self._local_mmap = None
        self._local_mmap_content = None
        # read from process by default
        #self._base = self._process()
        self._base = process
    
    def readWord(self, address):
        word = self._base.readWord(address)
        return word

    def readBytes(self, address, size):
        data = self._base.readBytes(address, size)
        return data

    def readStruct(self, address, struct):
        struct = self._base.readStruct(address, struct)
        struct._orig_address_ = address
        return struct

    def readArray(self, address, basetype, count):
        array = self._base.readArray(address, basetype, count)
        return array

    def isMmaped(self):
        return not (self._local_mmap is None)
        
    def mmap(self):
        ''' mmap-ed access gives a 20% perf increase on by tests '''
        # DO NOT USE ptrace.process.readArray on 64 bits.
        # It breaks stuff.
        # probably a bad cast statement on c_char_p
        # FIXME: the big perf increase is now gone. Howto cast pointer to bytes into ctypes array ?
        if not self.isMmaped():
            #self._process().readArray(self.start, ctypes.c_ubyte, len(self) ) # keep ref
            #self._local_mmap_content = self._process().readArray(self.start, ctypes.c_ubyte, len(self) ) # keep ref
            self._local_mmap_content = utils.bytes2array( self._process().readBytes(self.start, len(self)), ctypes.c_ubyte )
            log.debug('type array %s'%(type(self._local_mmap_content)))
            self._local_mmap = LocalMemoryMapping.fromAddress( self, ctypes.addressof(self._local_mmap_content) )
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
        
class LocalMemoryMapping(MemoryMapping):
    """
    Local memory mapping.
    The memory space is present in local ctypes space.
    """
    def __init__(self, address, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._local_mmap = (ctypes.c_ubyte * len(self)).from_address(int(address)) # DEBUG TODO byte or ubyte 
        self._address = ctypes.addressof(self._local_mmap)
        #self._vbase = self.start + self._address # shit, thats wraps up...
        self._bytebuffer = None

    def vtop(self, vaddr):
        ret = vaddr - self.start + self._address 
        if ret<self._address or ret>(self._address+len(self)):
            raise ValueError('0x%0.8x/0x%0.8x is not a valid vaddr for me'%(vaddr,ret))
        return ret

    def mmap(self):
        return self
        
    def readWord(self, vaddr ):
        """Address have to be aligned!"""
        laddr = self.vtop( vaddr )
        word = self.config.get_word_type().from_address(long(laddr)).value # is non-aligned a pb ?, indianess is at risk
        return word

    def readBytes1(self, vaddr, size):
        laddr = self.vtop( vaddr )
        #data = b''.join([ struct.pack('B',x) for x in self.readArray( vaddr, ctypes.c_ubyte, size) ] )
        data = ctypes.string_at(laddr, size) # real 0.5 % perf
        return data

    def readBufferBytes(self, vaddr, size):
        laddr = vaddr - self.start
        return self._bytebuffer[laddr:laddr+size]
    readBytes = readBytes1
    
    def readStruct(self, vaddr, struct):
        laddr = self.vtop( vaddr )
        struct = struct.from_address(int(laddr))
        #struct = struct.from_buffer_copy(struct.from_address(int(laddr)))
        struct._orig_address_ = vaddr
        return struct

    def readArray(self, vaddr, basetype, count):
        laddr = self.vtop( vaddr )
        array = (basetype *count).from_address(int(laddr))
        return array

    def getByteBuffer(self):
        if self._bytebuffer is None:
            self._bytebuffer = self.readBytes( self.start , len(self))
            self.readBytes = self.readBufferBytes
        return self._bytebuffer

    def initByteBuffer(self, data=None):
        self._bytebuffer = data

    def __getstate__(self):
        d = dict(self.__dict__)
        del d['_local_mmap']
        del d['_bytebuffer']
        return d
    
    @classmethod
    def fromAddress(cls, memoryMapping, content_address):
        el = cls( content_address, memoryMapping.start, memoryMapping.end, 
                        memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                        memoryMapping.inode, memoryMapping.pathname)
        el.init_config(memoryMapping.config)
        return el

    @classmethod
    def fromBytebuffer(cls, memoryMapping, content):
        content_array = utils.bytes2array(content, ctypes.c_ubyte)
        content_address = ctypes.addressof(content_array)
        el = cls( content_address, memoryMapping.start, memoryMapping.end, 
                        memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                        memoryMapping.inode, memoryMapping.pathname)
        el.init_config(memoryMapping.config)
        el.content_array_save_me_from_gc = content_array
        return el

class MemoryDumpMemoryMapping(MemoryMapping):
    """ 
    A memoryMapping wrapper around a memory file dump.
    A lazy loading is done for that file, to quick load MM, withouth copying content
    
    :param offset the offset in the memory dump file from which the start offset will be mapped for end-start bytes
    :param preload mmap the memory dump at init ( default)
    """
    def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP', preload=False):
        MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._memdump = memdump
        log.debug('memdump %s'%( memdump))
        self._base = None
        if preload:
            self._mmap()
    
    def useByteBuffer(self):
        # toddo use bitstring
        self._mmap().getByteBuffer() ## XXX FIXME buggy
        # force readBytes update
        self.readBytes = self._base.readBytes
    
    def getByteBuffer(self):
        return self._mmap().getByteBuffer() 
    
    def isMmaped(self):
        return not (self._base is None)
        
    def mmap(self):
        ''' mmap-ed access gives a 20% perf increase on by tests '''
        if not self.isMmaped():
            self._mmap()
        return self._base

    def unmmap(self):
        raise NotImplementedError

    def _mmap(self):
        ''' protected api '''
        # mmap.mmap has a full bytebuffer API, so we can use it as is for bytebuffer.
        # we have to get a ctypes pointer-able instance to make our ctypes structure read efficient.
        # sad we can't have a bytebuffer from that same raw memspace
        # we do not keep the bytebuffer in memory, because it's a lost of space in most cases.
        if self._base is None:
            if hasattr(self._memdump,'fileno'): # normal file. 
                if config.MMAP_HACK_ACTIVE: # XXX that is the most fucked up, non-portable fuck I ever wrote.
                    #print 'mmap_hack', self
                    #if self.pathname.startswith('/usr/lib'):
                    #    raise Exception
                    self._local_mmap_bytebuffer = mmap.mmap(self._memdump.fileno(), self.end-self.start, access=mmap.ACCESS_READ)
                    self._memdump.close()
                    self._memdump = None
                    # yeap, that right, I'm stealing the pointer value. DEAL WITH IT.
                    # this is a local memory hack, so self.config.get_word_type() is not involved.
                    heapmap = struct.unpack('L', (ctypes.c_ulong).from_address(id(self._local_mmap_bytebuffer) + 2*(ctypes.sizeof(ctypes.c_ulong)) ) )[0]
                    self._local_mmap_content = (ctypes.c_ubyte*(self.end-self.start)).from_address(int(heapmap))
                else: # fallback with no creepy hacks
                    log.warning('Memory Mapping content mmap-ed() (double copy of %s) : %s'%(self._memdump.__class__, self))
                    # we have the bytes
                    local_mmap_bytebuffer = mmap.mmap(self._memdump.fileno(), self.end-self.start, access=mmap.ACCESS_READ)
                    self._memdump.close()
                    # we need an ctypes
                    self._local_mmap_content = utils.bytes2array(local_mmap_bytebuffer, ctypes.c_ubyte)            
            else: # dumpfile, file inside targz ... any read() API really
                self._local_mmap_content = utils.bytes2array(self._memdump.read(), ctypes.c_ubyte)
                self._memdump.close()
                log.warning('Memory Mapping content copied to ctypes array : %s'%(self))
            # make that _base
            self._base = LocalMemoryMapping.fromAddress( self, ctypes.addressof(self._local_mmap_content) )
            log.debug('LocalMemoryMapping done.')
        #redirect stuff
        self.readWord = self._base.readWord
        self.readArray = self._base.readArray
        self.readBytes = self._base.readBytes
        self.readStruct = self._base.readStruct
        return self._base
    
    def readWord(self, vaddr):
        return self._mmap().readWord( vaddr )

    def readBytes(self, vaddr, size):
        return self._mmap().readBytes(vaddr, size)

    def readStruct(self, vaddr, structType):
        return self._mmap().readStruct(vaddr, structType)

    def readArray(self, vaddr, basetype, count):
        return self._mmap().readArray(vaddr, basetype, count)

    def __getstate__(self):
        d = dict(self.__dict__)
        if hasattr(self,'_memdump.name'):
            d['_memdump_filename'] = self._memdump.name
        d['_memdump'] = None
        d['_local_mmap'] = None
        d['_local_mmap_content'] = None
        d['_base'] = None
        d['_process'] = None
        return d
    
    def __del__(self):
        #we need to clean the mmap mess
        if hasattr(self, '_local_mmap_bytebuffer'):
            if hasattr(self._local_mmap_bytebuffer, 'close'):
                self._local_mmap_bytebuffer.close()
        pass
    
    @classmethod
    def fromFile(cls, memoryMapping, aFile):
        '''
            aFile must be able to read().
        '''
        return cls( aFile, memoryMapping.start, memoryMapping.end, 
                        memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                        memoryMapping.inode, memoryMapping.pathname)


class FileBackedMemoryMapping(MemoryDumpMemoryMapping):
    '''
        Don't mmap the memoryMap. use the file on disk to read data.
    '''
    def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
        MemoryDumpMemoryMapping.__init__(self, memdump, start, end, permissions, offset, major_device, minor_device, inode, pathname, preload=False)
        self._local_mmap = LazyMmap(self._memdump)
        log.debug( 'FileBackedMemoryMapping created')
        return

    def _mmap(self):
        ''' returns self to force super() to read through us    '''
        return self


    def vtop(self, vaddr):
        ret = vaddr - self.start
        if ret<0 or ret>len(self):
            raise ValueError('%x/%x is not a valid vaddr for me'%(vaddr,ret))
        return ret

    def readBytes(self, vaddr, size):
        laddr = self.vtop(vaddr)
        size = ctypes.sizeof((ctypes.c_ubyte *size))
        data = b''.join([ struct.pack('B',x) for x in self._local_mmap[laddr:laddr+size] ])
        return data

    def readStruct(self, vaddr, structType):
        laddr = self.vtop(vaddr)
        size = ctypes.sizeof(structType)
        ## YES you DO need to have a copy, otherwise you finish with a allocated
        ## struct in a read-only mmaped file. Not good if you want to changed members pointers after that.
        # but at the same time, why would you want to CHANGE anything ?
        struct = structType.from_buffer_copy(self._local_mmap[laddr:laddr+size], 0)
        struct._orig_address_ = vaddr
        return struct

        

    def readWord(self, vaddr):
        """Address have to be aligned!"""
        laddr = self.vtop(vaddr)
        word = self.config.get_word_type().from_buffer_copy(self._local_mmap[laddr:laddr+self.config.get_word_size()], 0).value # is non-aligned a pb ?
        return word

    def readArray(self, address, basetype, count):
        laddr = self.vtop(address)
        size = ctypes.sizeof((basetype *count))
        array = (basetype *count).from_buffer_copy(self._local_mmap[laddr:laddr+size], 0)
        return array
    
    @classmethod
    def fromFile(self, memoryMapping, memdump):
        """
            Transform a MemoryMapping to a file-backed MemoryMapping using FileBackedMemoryMapping.
            
            memoryMapping is the MemoryMapping instance.
            memdump is used as memory_mapping content.
            
        """
        return cls(memdump, memoryMapping.start, memoryMapping.end, 
                                memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
                                memoryMapping.inode, memoryMapping.pathname)

class FilenameBackedMemoryMapping(MemoryDumpMemoryMapping):
    '''
        Don't mmap the memoryMap. use the file name on disk to read data.
    '''
    def __init__(self, memdumpname, start, end, permissions='rwx-', offset=0x0, 
                                            major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
        MemoryDumpMemoryMapping.__init__(self, None, start, end, permissions, offset, 
                                                                            major_device, minor_device, inode, pathname, preload=False)
        self._memdumpname = memdumpname
        return 

    def _mmap(self):
        #import code
        #code.interact(local=locals())
        self._memdump = file(self._memdumpname,'rb')
        return MemoryDumpMemoryMapping._mmap(self)

class LazyMmap:
    ''' 
    lazy mmap no memory.
    '''
    def __init__(self,memdump):
        i = memdump.tell()
        try:
            memdump.seek(2**64)
        except OverflowError:
            memdump.seek(os.fstat(memdump.fileno()).st_size)
        self.size = memdump.tell()
        self.memdump_name = memdump.name
        memdump.seek(i)
        memdump.close()
    
    def __len__(self):
        return self.size
        
    def __getitem__(self,key):
        if type(key) == slice :
            start = key.start
            size = key.stop - key.start
        elif type(key) == int :
            start = key
            size = 1
        else :
            raise ValueError('bad index type')
        return self._get(start, size)
    
    def _get(self, offset,size):
        memdump = file(self.memdump_name, 'rb')
        memdump.seek(offset)
        me = utils.bytes2array(memdump.read(size) ,ctypes.c_ubyte)
        memdump.close()
        return me



class Mappings:
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


def readProcessMappings(process):
    """
    Read all memory mappings of the specified process.

    Return a list of MemoryMapping objects, or empty list if it's not possible
    to read the mappings.

    May raise a ProcessError.
    """
    maps = []
    if not HAS_PROC:
        return maps
    try:
        mapsfile = openProc(process.pid)
    except ProcError, err:
        raise ProcessError(process, "Unable to read process maps: %s" % err)

    from haystack import types    
    before = None
    # save the current ctypes module.
    mappings = Mappings(None)
    if True:
        import ctypes
        before = ctypes
    try:
        for line in mapsfile:
            line = line.rstrip()
            match = PROC_MAP_REGEX.match(line)
            if not match:
                raise ProcessError(process, "Unable to parse memory mapping: %r" % line)
            log.debug('readProcessMappings %s'%( str(match.groups())) )
            _map = ProcessMemoryMapping(
                #cfg,
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
        if type(mapsfile) is file:
            mapsfile.close()
    # set the target arch        
    mappings.init_config()
    # reposition the previous ctypes module.
    if True:
        ctypes = types.set_ctypes(before)
    return mappings

def readLocalProcessMappings():
    class P:
        pid = os.getpid()
        # we need that for the machine arch read.
        def readBytes(self, addr, size):
            import ctypes
            return ctypes.string_at(addr, size)

    return readProcessMappings(P()) # memory_mapping

