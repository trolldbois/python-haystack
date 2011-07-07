from ptrace.os_tools import HAS_PROC
if HAS_PROC:
     from ptrace.linux_proc import openProc, ProcError
from ptrace.debugger.process_error import ProcessError
from ptrace.ctypes_tools import formatAddress
import re
from weakref import ref
import ctypes, struct, mmap
# local
#from model import bytes2array # TODO check ctypes_tools.bytes2array in ptrace

import logging
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
    # Filename: '  /usr/bin/synergyc'
    r'(?: +(.*))?')

class MemoryMapping:
    """
    Process memory mapping (metadata about the mapping).

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
    def __init__(self, process, start, end, permissions, offset, major_device, minor_device, inode, pathname):
        self._process = ref(process)
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.major_device = major_device
        self.minor_device = minor_device
        self.inode = inode
        self.pathname = pathname
        self.local_mmap = None

    def __contains__(self, address):
        return self.start <= address < self.end

    def __str__(self):
        text = "%s-%s" % (formatAddress(self.start), formatAddress(self.end))
        if self.pathname:
            text += " => %s" % self.pathname
        text += " (%s)" % self.permissions
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

    def mmap(self):
      ''' mmap-ed access gives a 20% perf increase on by tests '''
      self.local_mmap = self._process().readArray(self.start, ctypes.c_ubyte, self.end-self.start)
      return self.local_mmap

    def readWord(self, address):
        """Address have to be aligned!"""
        if self.local_mmap : # WORD is type long
            laddr = ctypes.addressof(self.local_mmap) + address-self.start
            word = ctypes.c_ulong.from_address(laddr).value # is non-aligned a pb ?
        else:
            word = self._process().readWord(address)
        return word

    def readBytes(self, address, size):
        if self.local_mmap :
            laddr = address-self.start
            data = b''.join([ struct.pack('B',x) for x in self.local_mmap[laddr:laddr+size] ])
        else:
            data = self._process().readBytes(address, size)
        return data

    def readStruct(self, address, struct):
        if self.local_mmap :
            laddr = ctypes.addressof(self.local_mmap) + address-self.start
            struct = struct.from_address(laddr)
        else:
            struct = self._process().readStruct(address, struct)
        return struct

    def readArray(self, address, basetype, count):
        if self.local_mmap :
            laddr = ctypes.addressof(self.local_mmap) + address-self.start
            array = (basetype *count).from_address(laddr)
        else:
            array = self._process().readArray(address, basetype, count)
        return array

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

    def __getstate__(self):
      d = dict(self.__dict__)
      del d['_process'] #= d['_process'].pid
      #d['local_mmap'] = model.array2bytes(d['local_mmap'])
      del d['local_mmap']
      return d

    #def __setstate__(self, state):
    #  for k,v in state.items():
    #    self.__dict__[k] = v
    #  #d['_process'] = 
    #  #d['local_mmap'] = model.bytes2array(d['local_mmap'],ctypes.c_ubyte)
     

class MemoryDumpMemoryMapping(MemoryMapping):
    """ A memoryMapping wrapper around a memory file dump"""
    def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
        MemoryMapping.__init__(self, self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._process = None
        self.local_mmap = mmap.mmap(memdump.fileno(), end-start, access=mmap.ACCESS_READ)

    def _err(self):
        raise 
        
    def search(self, bytestr):
        self.local_mmap.find(bytestr)

    def readWord(self, address):
        """Address have to be aligned!"""
        laddr = self.vtop(address)
        word = ctypes.c_ulong.from_buffer_copy(self.local_mmap, laddr).value # is non-aligned a pb ?
        return word

    def readBytes(self, address, size):
        laddr = self.vtop(address)
        data = self.local_mmap[laddr:laddr+size]
        return data

    def readStruct(self, address, structType):
        from model import bytes2array # TODO check ctypes_tools.bytes2array in ptrace
        laddr = self.vtop(address)
        structLen = ctypes.sizeof(structType)
        st = self.local_mmap[laddr:laddr+structLen]
        structtmp = bytes2array(st, ctypes.c_ubyte)
        struct = structType.from_buffer(structtmp)
        return struct

    def readArray(self, address, basetype, count):
        laddr = self.vtop(address)
        array = (basetype *count).from_buffer_copy(self.local_mmap, laddr)
        return array

    def vtop(self, vaddr):
        return vaddr - self.start

    def __str__(self):
        text = "0x%lx-%s" % (self.start, formatAddress(self.end))
        text += " => %s" % self.pathname
        text += " (%s)" % self.permissions
        return text

def fileMemoryMapping_process(self):
  ''' fake it like a process and mmap it now'''
  import model
  if self.local_mmap is None:
    if hasattr(self.memdump,'fileno'):
      self.local_mmap = mmap.mmap(self.memdump.fileno(), self.end-self.start, access=mmap.ACCESS_READ)
      log.info('Lazy Memory Mapping content mmap-ed() : %s'%(self))
    else:
      # use that or mmap, anyway, we need to convert to ctypes :/ that costly
      self.local_mmap = model.bytes2array(self.memdump.read(), ctypes.c_ubyte)
      log.info('Lazy Memory Mapping content loaded : %s'%(self))
  return self

def FileMemoryMapping(memoryMapping, memdump):
  """ A memoryMapping wrapper backed by a around a memory file dump for mmap() 
  @param memoryMapping: a MemoryMapping
  @param memdump: memorydump File
  """
  import copy, types
  p = None
  m = None
  # we del _process
  if hasattr(memoryMapping,'_process'):
    p = memoryMapping._process
  # we keep local__map
  if not hasattr(memoryMapping,'local_mmap'):
    memoryMapping.local_mmap = None
  memoryMapping._process = None
  ret = copy.deepcopy(memoryMapping)
  if hasattr(memoryMapping,'_process'):
    memoryMapping._process = p
  ret.memdump = memdump
  ret._process = types.MethodType(fileMemoryMapping_process, ret, MemoryMapping)
  #if memoryMapping.local_mmap is not None:
  if not hasattr(ret,'local_mmap'):
    ret.local_mmap = None
  return ret

def getFileBackedMemoryMapping(memoryMapping, memdump):
  return FileBackedMemoryMapping(memdump, memoryMapping.start, memoryMapping.end, 
              memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device, 
              memoryMapping.inode, memoryMapping.pathname)

class LazyMmap:
  ''' lazy mmap no memory.
   useless.
  '''
  def __init__(self,memdump):
    memdump.seek(2**64)
    self.size = memdump.tell()
    self.memdump = memdump
  
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
    import model 
    self.memdump.seek(offset)
    #me = mmap.mmap(memdump.fileno(), end-start, access=mmap.ACCESS_READ)
    me = model.bytes2array(self.memdump.read(size) ,ctypes.c_ubyte)
    return me

class FileBackedMemoryMapping(MemoryDumpMemoryMapping):
  '''
    don't mmap the memoryMap. use the file to read offsets.
  '''
  def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP'):
    MemoryMapping.__init__(self, self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
    self.memdump = memdump
    self.local_mmap = LazyMmap(self.memdump)
    return    
  def readWord(self, address):
    """Address have to be aligned!"""
    laddr = self.vtop(address)
    size = ctypes.sizeof((ctypes.c_int))
    word = ctypes.c_ulong.from_buffer_copy(self.local_mmap[laddr:laddr+size], 0).value # is non-aligned a pb ?
    return word
  def readArray(self, address, basetype, count):
    laddr = self.vtop(address)
    size = ctypes.sizeof((basetype *count))
    array = (basetype *count).from_buffer_copy(self.local_mmap[laddr:laddr+size], 0)
    return array

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
        mapsfile = openProc("%s/maps" % process.pid)
    except ProcError, err:
        raise ProcessError(process, "Unable to read process maps: %s" % err)
    
    try:
        for line in mapsfile:
            line = line.rstrip()
            match = PROC_MAP_REGEX.match(line)
            if not match:
                raise ProcessError(process, "Unable to parse memoy mapping: %r" % line)
            map = MemoryMapping(
                process,
                int(match.group(1), 16),
                int(match.group(2), 16),
                match.group(3),
                int(match.group(4), 16),
                int(match.group(5), 16),
                int(match.group(6), 16),
                int(match.group(7)),
                match.group(8))
            maps.append(map)
    finally:
        mapsfile.close()
    return maps

