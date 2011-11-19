#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import mmap, logging
import os, time

from dbg import PtraceDebugger
# local
from haystack import memory_mapping
from haystack import memory_dumper

log = logging.getLogger('mapper')

MAX_DUMP_SIZE=200000000

class MemoryMapper:
  def __init__(self, args):
    # args are checked by the parser
    if not (args.pid is None):
      mappings = self.initPid(args)
    elif not (args.memfile is None):
      mappings = self.initMemfile(args)
    elif not (args.dumpfile is None):
      mappings = self.initProcessDumpfile(args)
    self.mappings = mappings
    return
  
  def getMappings(self):
    return self.mappings
    
  def initProcessDumpfile(self,args):
    loader = memory_dumper.ProcessMemoryDumpLoader(args.dumpfile)
    mappings = loader.getMappings()
    return mappings

  def initMemfile(self,args):
    size = os.fstat(args.memfile.fileno()).st_size
    if size > MAX_DUMP_SIZE:
      mem = memory_mapping.FileBackedMemoryMapping(args.memfile, args.baseOffset, args.baseOffset+size) ## is that valid ?
      log.warning('Dump file size is big. Using file backend memory mapping. Its gonna be slooow')
    else:
      mem = memory_mapping.MemoryDumpMemoryMapping(args.memfile, args.baseOffset, args.baseOffset+size) ## is that valid ?
    mappings = memory_mapping.Mappings([mem], args.memfile.name)
    return mappings

  def initPid(self, args):
    dbg = PtraceDebugger()
    process = dbg.addProcess(args.pid, is_attached=False)
    print process.__dict__.keys()
    if process is None:
      log.error("Error initializing Process debugging for %d"% args.pid)
      raise IOError
      # ptrace exception is raised before that
    mappings = memory_mapping.readProcessMappings(process)
    t0 = time.time()
    for m in mappings :
      if args.mmap:
        ### mmap memory in local space
        m.mmap()
        log.debug('mmap() : %d'%(len(m.mmap())))
    if args.mmap:
      ### mmap done, we can release process...
      process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))
    return mappings
