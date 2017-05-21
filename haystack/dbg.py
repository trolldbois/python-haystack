#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import platform
import time


try:
    import ptrace
    from ptrace import os_tools
    from ptrace.debugger import debugger
    from ptrace import linux_proc
    from ptrace.debugger import process_error

except ImportError as e:
    pass

try:
    import winappdbg

except ImportError as e:
    pass

log = logging.getLogger("gbd")


class IProcessDebugger(object):
    def get_process(self):
        raise NotImplementedError(self)

    def quit(self):
        raise NotImplementedError(self)


class IProcess(object):
    def get_pid(self):
        raise NotImplementedError(self)

    def get_mappings_line(self):
        raise NotImplementedError(self)

    def read_word(self, address):
        raise NotImplementedError(self)

    def read_bytes(self, address, size):
        raise NotImplementedError(self)

    def read_struct(self, address, struct):
        raise NotImplementedError(self)

    def read_array(self, address, basetype, count):
        raise NotImplementedError(self)


class MyPTraceDebugger(IProcessDebugger):
    def __init__(self, pid):
        # /proc mappings debugger
        if not os_tools.HAS_PROC:
            raise TypeError('We only support /proc ptrace')
        # ptrace debugguer
        self.my_debugger = debugger.PtraceDebugger()
        proc = self.my_debugger.addProcess(pid, is_attached=False)
        self.process = MyPTraceProcess(pid, proc)

    def get_process(self):
        return self.process

    def quit(self):
        self.process.resume()
        self.my_debugger.deleteProcess(process=self.process)
        self.process = None


class MyWinAppDebugger(IProcessDebugger):

    def __init__(self, pid):
        winappdbg.System.request_debug_privileges()
        self.procs = []
        proc = winappdbg.Process(pid)
        self.process = MyWinAppDbgProcess(pid, proc)

    def get_process(self):
        return self.process

    def quit(self):
        self.process.resume()
        self.process = None


class MyPTraceProcess(IProcess):
    def __init__(self, pid, ptrace_process):
        self.ptrace_process = ptrace_process
        self.pid = pid

    def get_pid(self):
        return self.pid

    def resume(self):
        self.ptrace_process.cont()

    def get_mappings_line(self):
        return linux_proc.openProc("%s/maps" % self.get_pid()).readlines()

    def read_word(self, address):
        return self.ptrace_process.readWord(address)

    def read_bytes(self, address, size):
        return self.ptrace_process.readBytes(address, size)

    def read_struct(self, address, struct):
        return self.ptrace_process.readStruct(address, struct)

    def read_array(self, address, basetype, count):
        return self.ptrace_process.readArray(address, basetype, count)


class MyWinAppDbgProcess(IProcess):
    def __init__(self, pid, winapp_process):
        self.winapp_process = winapp_process
        self.pid = pid

    def get_pid(self):
        return self.pid

    def resume(self):
        self.winapp_process.resume()

    def get_mappings_line(self):
        """ return proc maps """
        fileName = self.winapp_process.get_filename()
        memoryMap = self.winapp_process.get_memory_map()
        mappedFilenames = self.winapp_process.get_mapped_filenames()
        # 08048000-080b0000 r-xp 0804d000 fe:01 3334030    /usr/myfile
        lines = []
        for mbi in memoryMap:
            if not mbi.is_readable():
                continue
            addr = ''
            perm = '--- '
            offset = ''
            device = ''
            inode = ''
            filename = ''

            # Address and size of memory block.
            BaseAddress = winappdbg.HexDump.address(mbi.BaseAddress)
            RegionSize = winappdbg.HexDump.address(mbi.RegionSize)

            # State (free or allocated).
            mbiState = mbi.State
            if mbiState == winappdbg.win32.MEM_RESERVE:
                State = "Reserved"
            elif mbiState == winappdbg.win32.MEM_COMMIT:
                State = "Commited"
            elif mbiState == winappdbg.win32.MEM_FREE:
                State = "Free"
            else:
                State = "Unknown"

            # Page protection bits (R/W/X/G).
            if mbiState != winappdbg.win32.MEM_COMMIT:
                Protect = "--- "
            else:
                mbiProtect = mbi.Protect
                if mbiProtect & winappdbg.win32.PAGE_NOACCESS:
                    Protect = "--- "
                elif mbiProtect & winappdbg.win32.PAGE_READONLY:
                    Protect = "R-- "
                elif mbiProtect & winappdbg.win32.PAGE_READWRITE:
                    Protect = "RW- "
                elif mbiProtect & winappdbg.win32.PAGE_WRITECOPY:
                    Protect = "RC- "
                elif mbiProtect & winappdbg.win32.PAGE_EXECUTE:
                    Protect = "--X "
                elif mbiProtect & winappdbg.win32.PAGE_EXECUTE_READ:
                    Protect = "R-X "
                elif mbiProtect & winappdbg.win32.PAGE_EXECUTE_READWRITE:
                    Protect = "RWX "
                elif mbiProtect & winappdbg.win32.PAGE_EXECUTE_WRITECOPY:
                    Protect = "RCX "
                else:
                    Protect = "??? "
                '''
                if     mbiProtect & win32.PAGE_GUARD:
                        Protect += "G"
                #else:
                #        Protect += "-"
                if     mbiProtect & win32.PAGE_NOCACHE:
                        Protect += "N"
                #else:
                #        Protect += "-"
                if     mbiProtect & win32.PAGE_WRITECOMBINE:
                        Protect += "W"
                #else:
                #        Protect += "-"
                '''
            perm = Protect

            # Type (file mapping, executable image, or private memory).
            mbiType = mbi.Type
            if mbiType == winappdbg.win32.MEM_IMAGE:
                Type = "Image"
            elif mbiType == winappdbg.win32.MEM_MAPPED:
                Type = "Mapped"
            elif mbiType == winappdbg.win32.MEM_PRIVATE:
                Type = "Private"
            elif mbiType == 0:
                Type = ""
            else:
                Type = "Unknown"

            log.debug(BaseAddress)
            # FIXME get arch, 08 or 04... ?
            addr = '%08x-%08x' % (int(BaseAddress, 16), int(BaseAddress, 16) + int(RegionSize, 16))
            perm = perm.lower()
            offset = '00000000'
            device = 'fe:01'
            inode = 24422442
            filename = mappedFilenames.get(mbi.BaseAddress, ' ')

            # 08048000-080b0000 r-xp 0804d000 fe:01 3334030    /usr/myfile
            lines.append('%s %s %s %s %s %s\n' % (addr, perm, offset, device, inode, filename))
            log.debug('%s %s %s %s %s %s\n' % (addr, perm, offset, device, inode, filename))
        return lines

    def read_word(self, address):
        return self.winapp_process.read_word(address)

    def read_bytes(self, address, size):
        return self.winapp_process.read(address, size)

    def read_struct(self, address, struct):
        return self.winapp_process.read_struct(address, struct)

    def read_array(self, address, basetype, count):
        return self.winapp_process.read_structure(address, basetype * count)


def get_debugger(pid):
    if platform.system() != 'Windows':
        return MyPTraceDebugger(pid)
    else:
        return MyWinAppDebugger(pid)


def make_local_process_memory_handler(pid, use_mmap=True):
    if not isinstance(pid, (int, long)):
        raise TypeError('PID should be a number')
    from haystack.mappings import process
    my_debugger = get_debugger(pid)
    _memory_handler = process.make_process_memory_handler(my_debugger.get_process())
    t0 = time.time()
    for m in _memory_handler:
        if use_mmap:
            # force to mmap the memory in local space
            m.mmap()
            log.debug('mmap() size:%d', len(m.mmap()))
    if use_mmap:
        # mmap done, we can release process...
        my_debugger.get_process().resume()
        log.info('MemoryHandler mmaped, process released after %02.02f secs', time.time() - t0)
    return _memory_handler
