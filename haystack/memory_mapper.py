#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import mmap, logging
import os, time

from dbg import PtraceDebugger
# local
from memory_mapping import MemoryDumpMemoryMapping , FileBackedMemoryMapping, readProcessMappings
import memory_dumper

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
      mem = FileBackedMemoryMapping(args.memfile, args.baseOffset, args.baseOffset+size) ## is that valid ?
      log.warning('Dump file size is big. Using file backend memory mapping. Its gonna be slooow')
    else:
      mem = MemoryDumpMemoryMapping(args.memfile, args.baseOffset, args.baseOffset+size) ## is that valid ?
    mappings=[mem]
    return mappings

  def initPid(self, args):
    dbg = PtraceDebugger()
    process = dbg.addProcess(args.pid, is_attached=False)
    if process is None:
      log.error("Error initializing Process debugging for %d"% args.pid)
      raise IOError
      # ptrace exception is raised before that
    tmp = readProcessMappings(process)
    mappings=[]
    remains=[]
    t0=time.time()
    for m in tmp :
      if hasattr(args,'mmap') and args.mmap:
        ### mmap memory in local space
        m.mmap()
        log.debug('mmap() : %d'%(len(m.mmap())))
      if ( m.pathname == '[heap]' or 
           m.pathname == '[vdso]' or
           m.pathname == '[stack]' or
           m.pathname is None ):
        mappings.append(m)
        continue
      remains.append(m)
    #tmp = [x for x in remains if not x.pathname.startswith('/')] # delete memmapped dll
    tmp=remains
    tmp.sort(key=lambda x: x.start )
    tmp.reverse()
    mappings.extend(tmp)
    mappings.reverse()
    if hasattr(args,'mmap') and args.mmap:
      ### mmap done, we can release process...
      process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))
    return mappings
