#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import platform
if platform.system() != 'Windows':
  # ptrace debugguer
  import ptrace.debugger.debugger #import PtraceDebugger
  PtraceDebugger = ptrace.debugger.debugger.PtraceDebugger
  # proc mapping
  from ptrace.debugger import process_error
  ProcessError = process_error.ProcessError
  import ptrace.os_tools #import HAS_PROC
  if ptrace.os_tools.HAS_PROC:
    import ptrace.linux_proc #import openProc, ProcError
    def openProc(pid):
      return ptrace.linux_proc.openProc("%s/maps" % pid)
    ProcError = ptrace.linux_proc.ProcError
    HAS_PROC=ptrace.os_tools.HAS_PROC
  else:
    ProcError = ProcessError
    HAS_PROC=True

  formatAddress = ptrace.ctypes_tools.formatAddress 

else:
  import ctypes
  import winappdbg
  from winappdbg import win32, Process, System, HexDump, HexInput, CrashDump
  class WinAppDebugger:
    def addProcess(self,pid, is_attached=False):
      proc = Process(pid)
      proc.pid = pid
      return proc
  #globals  
  PtraceDebugger = WinAppDebugger
  HAS_PROC = True
  
  System.request_debug_privileges()
  
  # get process maps
  def openProc(pid):
    ''' return proc maps '''
    process         = Process(pid)
    fileName        = process.get_filename()
    memoryMap       = process.get_memory_map()
    mappedFilenames = process.get_mapped_filenames()
    # 08048000-080b0000 r-xp 0804d000 fe:01 3334030  /usr/myfile  
    lines = []
    for mbi in memoryMap:
      addr = ''
      perm = '--- ' 
      offset=''
      device = ''
      inode=''
      filename = ''
      
        
      # Address and size of memory block.
      BaseAddress = HexDump.address(mbi.BaseAddress)
      RegionSize  = HexDump.address(mbi.RegionSize)

      # State (free or allocated).
      mbiState = mbi.State
      if   mbiState == win32.MEM_RESERVE:
          State   = "Reserved"
      elif mbiState == win32.MEM_COMMIT:
          State   = "Commited"
      elif mbiState == win32.MEM_FREE:
          State   = "Free"
      else:
          State   = "Unknown"

      # Page protection bits (R/W/X/G).
      if mbiState != win32.MEM_COMMIT:
        Protect = "--- "
      else:
        mbiProtect = mbi.Protect
        if   mbiProtect & win32.PAGE_NOACCESS:
            Protect = "--- "
        elif mbiProtect & win32.PAGE_READONLY:
            Protect = "R-- "
        elif mbiProtect & win32.PAGE_READWRITE:
            Protect = "RW- "
        elif mbiProtect & win32.PAGE_WRITECOPY:
            Protect = "RC- "
        elif mbiProtect & win32.PAGE_EXECUTE:
            Protect = "--X "
        elif mbiProtect & win32.PAGE_EXECUTE_READ:
            Protect = "R-X "
        elif mbiProtect & win32.PAGE_EXECUTE_READWRITE:
            Protect = "RWX "
        elif mbiProtect & win32.PAGE_EXECUTE_WRITECOPY:
            Protect = "RCX "
        else:
            Protect = "??? "
        '''    
        if   mbiProtect & win32.PAGE_GUARD:
            Protect += "G"
        #else:
        #    Protect += "-"
        if   mbiProtect & win32.PAGE_NOCACHE:
            Protect += "N"
        #else:
        #    Protect += "-"
        if   mbiProtect & win32.PAGE_WRITECOMBINE:
            Protect += "W"
        #else:
        #    Protect += "-"
        '''
      perm = Protect
      
      # Type (file mapping, executable image, or private memory).
      mbiType = mbi.Type
      if   mbiType == win32.MEM_IMAGE:
          Type    = "Image"
      elif mbiType == win32.MEM_MAPPED:
          Type    = "Mapped"
      elif mbiType == win32.MEM_PRIVATE:
          Type    = "Private"
      elif mbiType == 0:
          Type    = ""
      else:
          Type    = "Unknown"
      
      log.debug( BaseAddress)
      addr = '%08x-%08x'%(int(BaseAddress,16), int(BaseAddress,16)+int(RegionSize,16) )
      perm = perm.lower()
      offset = '00000000'
      device = 'fe:01'
      inode = 24422442
      filename = mappedFilenames.get(mbi.BaseAddress, ' ')

      # 08048000-080b0000 r-xp 0804d000 fe:01 3334030  /usr/myfile  
      lines.append('%s %s %s %s %s %s\n'%(addr,perm,offset,device,inode,filename) )
      log.debug(   '%s %s %s %s %s %s\n'%(addr,perm,offset,device,inode,filename) )

    return lines
    
    process         = Process(pid)
    fileName        = process.get_filename()
    memoryMap       = process.get_memory_map()
    mappedFilenames = process.get_mapped_filenames()
    if fileName:
        log.debug( "Memory map for %d (%s):" % (pid, fileName) )
    else:
        log.debug( "Memory map for %d:" % pid )
    log.debug( '%d filenames'% len(mappedFilenames) )
    log.debug('')
    log.debug( '%d memorymap'%len(memoryMap) )

    readable    = 0
    writeable   = 0
    executable  = 0
    private     = 0
    mapped      = 0
    image       = 0
    total       = 0
    for mbi in memoryMap:
      size = mbi.RegionSize
      if not mbi.is_free():
        total += size
      if mbi.is_readable():
        readable += size
      if mbi.is_writeable():
        writeable += size
      if mbi.is_executable():
        executable += size
      if mbi.is_private():
        private += size
      if mbi.is_mapped():
        mapped += size
      if mbi.is_image():
        image += size
    width = len(str(total))
    log.debug ("  %%%ds bytes of readable memory" % width) % int(readable)
    log.debug ("  %%%ds bytes of writeable memory" % width) % int(writeable)
    log.debug ("  %%%ds bytes of executable memory" % width) % int(executable)
    log.debug ("  %%%ds bytes of private memory" % width) % int(private)
    log.debug ("  %%%ds bytes of mapped memory" % width) % int(mapped)
    log.debug ("  %%%ds bytes of image memory" % width) % int(image)
    log.debug ("  %%%ds bytes of total memory" % width) % int(total)
    log.debug('')
    return
  
  class ProcessError(Exception):
    pass
  ProcError=ProcessError
  
  def formatAddress(addr):
    if ctypes.sizeof(ctypes.c_void_p) == 4:
      return u"0x%08x" % addr
    else:
      return u"0x%016x" % addr
