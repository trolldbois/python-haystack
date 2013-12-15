#!/usr/bin/env python
# -*- coding: utf-8 -*-
# # 
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
# Windows mappings code stolen from winappdbg
#
# Copyright (c) 2009-2010, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import logging

log=logging.getLogger("gbd")

import ctypes
if hasattr(ctypes, 'original_c_char_p'):
  #model is already active, ptrace is not loaded, need to go back to original c_char_p before ptrace loads
  ctypes.__haystack_c_char_p = ctypes.c_char_p
  ctypes.c_char_p = ctypes.original_c_char_p
  #print 'dbg before ptrace loading', ctypes.c_char_p

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

  formatAddress = ptrace.ctypes_tools.formatAddress #TODO move to utils

else:
  import ctypes
  import winappdbg
  from winappdbg import win32, Process, System, HexDump, HexInput, CrashDump
  class WinAppDebugger:
    def __init__(self):
      self.procs = []
    def addProcess(self,pid, is_attached=False):
      proc = Process(pid)
      proc.pid = pid
      self.procs.append(proc)
      def readArray(vaddr, typ, s):
        #print 'HIHIHI',proc, vaddr, typ, s
        return proc.read_structure( vaddr, typ*s)
      proc.readArray = readArray 
      proc.cont = proc.resume 
      return proc
    def deleteProcess(self,process):
      self.procs.remove(process)
    def quit(self):
      pass
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
      if not mbi.is_readable():
        continue
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

    ##generate_memory_snapshot(self, minAddr=None, maxAddr=None)
    return lines
    
    #process.suspend()
    #try:
    #    snapshot = process.generate_memory_snapshot()
    #    for mbi in snapshot:
    #        print HexDump.hexblock(mbi.content, mbi.BaseAddress)
    #finally:
    #    process.resume()
    
    
    # process.read_structure()
    
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
  
  def formatAddress(addr): #TODO move to utils
    if ctypes.sizeof(ctypes.c_void_p) == 4:
      return u"0x%08x" % addr
    else:
      return u"0x%016x" % addr


if hasattr(ctypes, '__haystack_c_char_p'):
  #model is already active, ptrace is not loaded, die biatch !
  ctypes.c_char_p = ctypes.__haystack_c_char_p
  del ctypes.__haystack_c_char_p #= ctypes.c_char_p
  #print 'dbg after ptrace loading', ctypes.c_char_p


