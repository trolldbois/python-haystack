#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Gets memory mappings from a PID or a haystack dump."""

import mmap
import logging
import os
import time

from haystack.dbg import PtraceDebugger
# local
from haystack.config import Config
from haystack import memory_mapping
from haystack import dump_loader

log = logging.getLogger('mapper')

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class MemoryMapper:
  """Build MemoryMappings from a PID or a haystack memory dump."""
  def __init__(self, pid=None, mmap=True, memfile=None, baseOffset=None, dumpname=None):
    # args are checked by the parser
    if not (pid is None):
      mappings = self.initPid(pid, mmap)
    elif not (memfile is None):
      mappings = self.initMemfile(memfile, baseOffset)
    elif not (dumpname is None):
      mappings = self.initProcessDumpfile(dumpname)
    self.mappings = mappings
    return
  
  def getMappings(self):
    return self.mappings
    
  def initProcessDumpfile(self, dumpname):
    loader = dump_loader.ProcessMemoryDumpLoader(dumpname)
    mappings = loader.getMappings()
    return mappings

  def initMemfile(self, memfile, baseOffset):
    size = os.fstat(memfile.fileno()).st_size
    if size > Config.MAX_MAPPING_SIZE_FOR_MMAP:
      mem = memory_mapping.FileBackedMemoryMapping(memfile, baseOffset, baseOffset+size) ## is that valid ?
      log.warning('Dump file size is big. Using file backend memory mapping. Its gonna be slooow')
    else:
      mem = memory_mapping.MemoryDumpMemoryMapping(memfile, baseOffset, baseOffset+size) ## is that valid ?
    mappings = memory_mapping.Mappings([mem], memfile.name)
    return mappings

  def initPid(self, pid, mmap):
    if not isinstance(pid, (int, long)):
      raise TypeError('PID should be a number')
    dbg = PtraceDebugger()
    process = dbg.addProcess(pid, is_attached=False)
    if process is None:
      log.error("Error initializing Process debugging for %d"% pid)
      raise IOError
      # ptrace exception is raised before that
    mappings = memory_mapping.readProcessMappings(process)
    t0 = time.time()
    for m in mappings :
      if mmap:
        ### mmap memory in local space
        m.mmap()
        log.debug('mmap() : %d'%(len(m.mmap())))
    if mmap:
      ### mmap done, we can release process...
      process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))
    return mappings

