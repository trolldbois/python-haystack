

import os
import logging
import re
import ctypes
import struct
import mmap
from weakref import ref

# local
from dbg import openProc, ProcError, ProcessError, HAS_PROC, formatAddress 
import utils

log = logging.getLogger('memory_mapping')

'''
Memory mappings.
- MemoryMapping : memory mapping metadata
- ProcessMemoryMapping: memory space from a live process with the possibility to mmap the memspace at any moment.
- LocalMemoryMapping .fromAddress: memorymapping that lives in local space in a ctypes buffer. 
- MemoryDumpMemoryMapping .fromFile : memory space from a raw file, with lazy loading capabilities.
- FileBackedMemoryMapping .fromFile : memory space based on a file, with direct read no cache from file.
'''


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
  WORDSIZE = ctypes.sizeof(ctypes.c_ulong)
  WORDTYPE = ctypes.c_ulong
  def __init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname):
    self.start = start
    self.end = end
    self.permissions = permissions
    self.offset = offset
    self.major_device = major_device
    self.minor_device = minor_device
    self.inode = inode
    self.pathname = pathname

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
    return vaddr - self.start
    
  # ---- to implement if needed
  def readWord(self, address):
    raise NotImplementedError
  def readBytes(self, address, size):
    raise NotImplementedError
  def readStruct(self, address, struct):
    raise NotImplementedError
  def readArray(self, address, basetype, count):
    raise NotImplementedError


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
    self._base = self._process()
  
  def readWord(self, address):
    word = self._base.readWord(address)
    return word

  def readBytes(self, address, size):
    data = self._base.readBytes(address, size)
    return data

  def readStruct(self, address, struct):
    struct = self._base.readStruct(address, struct)
    return struct

  def readArray(self, address, basetype, count):
    array = self._base.readArray(address, basetype, count)
    return array

  def isMmaped(self):
    return not (self._local_mmap is None)
    
  def mmap(self):
    ''' mmap-ed access gives a 20% perf increase on by tests '''
    if not self.isMmaped():
      self._local_mmap_content = self._process().readArray(self.start, ctypes.c_ubyte, len(self) ) # keep ref
      #self._local_mmap = self._process().read(self.start, self.end-self.start)
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
    self._local_mmap = (ctypes.c_byte * len(self)).from_address(address)
    self._address = ctypes.addressof(self._local_mmap)
    #self._vbase = self.start + self._address # shit, thats wraps up...
    self._bytebuffer = None

  def vtop(self, vaddr):
    return vaddr - self.start + self._address 

  def readWord(self, vaddr ):
    """Address have to be aligned!"""
    laddr = self.vtop( vaddr )
    word = MemoryMapping.WORDTYPE.from_address(laddr).value # is non-aligned a pb ?, indianess is at risk
    return word

  def readBytes(self, vaddr, size):
    laddr = vaddr - self.start
    #data = b''.join([ struct.pack('B',x) for x in self._local_mmap[laddr:laddr+size] ])
    data = b''.join([ struct.pack('B',x) for x in self.readArray( vaddr, ctypes.c_ubyte, size) ] )
    return data
  
  def readStruct(self, vaddr, struct):
    laddr = self.vtop( vaddr )
    struct = struct.from_address(laddr)
    return struct

  def readArray(self, vaddr, basetype, count):
    laddr = self.vtop( vaddr )
    array = (basetype *count).from_address(laddr)
    return array

  def getByteBuffer(self):
    if self._bytebuffer is None:
      self._bytebuffer = self.readBytes( self.start , len(self))
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
    return cls( content_address, memoryMapping.start, memoryMapping.end, 
            memoryMapping.permissions, memoryMapping.offset, memoryMapping.major_device, memoryMapping.minor_device,
            memoryMapping.inode, memoryMapping.pathname)
      

class MemoryDumpMemoryMapping(MemoryMapping):
  """ 
  A memoryMapping wrapper around a memory file dump.
  A lazy loading is done for that file, to quick load MM, withouth copying content
  
  @param offset the offset in the memory dump file from which the start offset will be mapped for end-start bytes
  @param preload mmap the memory dump at init ( default)
  """
  def __init__(self, memdump, start, end, permissions='rwx-', offset=0x0, major_device=0x0, minor_device=0x0, inode=0x0, pathname='MEMORYDUMP', preload=False):
    MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
    self._memdump = memdump
    self._base = None
    s = len(LazyMmap(self._memdump))
    if offset > s:
      raise ValueError('offset 0x%x too big for filesize 0x%x'%(offset, s))
    if preload:
      self._mmap()
  
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
    # we do not keep the btyebuffer in memory, because it's a lost of space in most cases.
    if self._base is None:
      if hasattr(self._memdump,'fileno'): # normal file. mmap kinda useless i suppose.
        log.warning('Memory Mapping content mmap-ed() (double copy) : %s'%(self))
        local_mmap_bytebuffer = mmap.mmap(self._memdump.fileno(), self.end-self.start, access=mmap.ACCESS_READ)
        self._local_mmap_content = utils.bytes2array(local_mmap_bytebuffer, ctypes.c_ubyte)
      else: # dumpfile, file inside targz ... any read() API really
        self._local_mmap_content = utils.bytes2array(self._memdump.read(), ctypes.c_ubyte)
        log.warning('Memory Mapping content copied to ctypes array : %s'%(self))
      # make that _base
      self._base = LocalMemoryMapping.fromAddress( self, ctypes.addressof(self._local_mmap_content) )
      log.info('LocalMemoryMapping done.')
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
    return

  def _mmap(self):
    ''' returns self to force super() to read through us  '''
    return self

  def vtop(self, vaddr):
    return vaddr - self.start

  def readBytes(self, vaddr, size):
    laddr = self.vtop(vaddr)
    size = ctypes.sizeof((ctypes.c_ubyte *count))
    data = b''.join([ struct.pack('B',x) for x in self._local_mmap[laddr:laddr+size] ])
    return data

  def readStruct(self, vaddr, structType):
    laddr = self.vtop(vaddr)
    size = ctypes.sizeof(structType)
    stspace = structType.from_buffer_copy(self._local_mmap[laddr:laddr+size], 0).value # is non-aligned a pb ?
    return self._mmap().readStruct(vaddr, structType)

  def readWord(self, vaddr):
    """Address have to be aligned!"""
    laddr = self.vtop(vaddr)
    word = MemoryMapping.WORDTYPE.from_buffer_copy(self._local_mmap[laddr:laddr+MemoryMapping.WORDSIZE], 0).value # is non-aligned a pb ?
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
    self.memdump = memdump
    memdump.seek(i)
  
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
    self.memdump.seek(offset)
    #me = mmap.mmap(memdump.fileno(), end-start, access=mmap.ACCESS_READ)
    me = utils.bytes2array(self.memdump.read(size) ,ctypes.c_ubyte)
    return me



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
  
  try:
    for line in mapsfile:
      line = line.rstrip()
      match = PROC_MAP_REGEX.match(line)
      if not match:
        raise ProcessError(process, "Unable to parse memoy mapping: %r" % line)
      map = ProcessMemoryMapping(
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
    if type(mapsfile) is file:
      mapsfile.close()
  return maps

