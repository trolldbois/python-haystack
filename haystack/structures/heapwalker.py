#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
import logging
from haystack import types

log = logging.getLogger('heapwalker')

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class HeapWalker(object):

    def __init__(self, mappings, mapping, offset=0):
        self._mappings = mappings
        self._mapping = mapping
        self._offset = offset
        self._init_heap()

    def _init_heap(self):
        raise NotImplementedError('Please implement all methods')

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def get_free_chunks(self):
        """ returns all free chunks in the heap (addr,size) """
        raise NotImplementedError('Please implement all methods')


# TODO make a virtual function that plays libc or win32 ?
# or put that in the MemoryMappings ?
# or in the context ?


def detect_os(mappings):
    """Arch independent way to assess the os of a captured process"""
    linux = winxp = win7 = 0
    for pathname in [m.pathname.lower() for m in mappings
                     if m.pathname is not None and m.pathname != '']:
        if '\\system32\\' in pathname:
            winxp += 1
            win7 += 1
        if 'ntdll.dll' in pathname:
            winxp += 1
            win7 += 1
        elif 'Documents and Settings' in pathname:
            winxp += 1
        elif 'xpsp2res.dll' in pathname:
            winxp += 1
        elif 'SysWOW64' in pathname:
            win7 += 1
        elif '\\wer.dll' in pathname:
            win7 += 1
        elif '[heap]' in pathname:
            linux += 1
        elif '[vdso]' in pathname:
            linux += 1
        elif '/usr/lib/' in pathname:
            linux += 1
        elif '/' == pathname[0]:
            linux += 1
    log.debug(
        'detect_os: scores linux:%d winxp:%d win7:%d' %
        (linux, winxp, win7))
    scores = max(linux, max(winxp, win7))
    if scores == linux:
        return 'linux'
    elif scores == winxp:
        return 'winxp'
    elif scores == win7:
        return 'win7'


def detect_cpu(mappings, os_name=None):
    if os_name is None:
        os_name = detect_os(mappings)
    cpu = 'unknown'
    if os_name == 'linux':
        cpu = _detect_cpu_arch_elf(mappings)
    elif os_name == 'winxp' or os_name == 'win7':
        cpu = _detect_cpu_arch_pe(mappings)
    return cpu


def _detect_cpu_arch_pe(mappings):
    import pefile
    # get the maps with read-only data
    # find the executable image and get the PE header
    pe = None
    for m in mappings:
        # volatility dumps VAD differently than winappdbg
        # we have to look at all mappings
        # if m.permissions != 'r--':
        #    continue
        try:
            head = m.readBytes(m.start, 0x1000)
            pe = pefile.PE(data=head, fast_load=True)
            # only get the dirst one that works
            if pe is None:
                continue
            break
        except pefile.PEFormatError as e:
            pass
    machine = pe.FILE_HEADER.Machine
    arch = pe.OPTIONAL_HEADER.Magic
    if arch == 0x10b:
        return '32'
    elif arch == 0x20b:
        return '64'
    else:
        raise NotImplementedError('MACHINE is %s' % (pe.e_machine))
    return


def _detect_cpu_arch_elf(mappings):
    from haystack.structures.libc.ctypes_elf import struct_Elf_Ehdr
    # find an executable image and get the ELF header
    for m in mappings:
        if 'r-xp' not in m.permissions:
            continue
        try:
            head = m.readBytes(m.start, 0x40)  # 0x34 really
        except Exception as e:
            continue
        x = struct_Elf_Ehdr.from_buffer_copy(head)
        log.debug('MACHINE:%s pathname:%s' % (x.e_machine, m.pathname))
        if x.e_machine == 3:
            return '32'
        elif x.e_machine == 62:
            return '64'
        else:
            continue
    raise NotImplementedError('MACHINE has not been found.')


def make_heap_walker(mappings):
    """try to find what type of heaps are """
    from haystack.mappings import base
    if not isinstance(mappings, base.Mappings):
        raise TypeError('Feed me a Mappings')
    # ctypes is preloaded with proper arch
    os_name = mappings.get_os_name()
    if os_name == 'linux':
        from haystack.structures.libc import libcheapwalker
        return libcheapwalker.LibcHeapFinder()
    elif os_name == 'winxp':
        from haystack.structures.win32 import winheapwalker
        return winheapwalker.WinHeapFinder()
    elif os_name == 'win7':
        from haystack.structures.win32 import win7heapwalker
        return win7heapwalker.Win7HeapFinder()
    else:
        raise NotImplementedError(
            'Heap Walker not found for os %s' %
            (os_name))


class HeapFinder(object):

    def __init__(self):#, ctypes):
        #ctypes = types.set_ctypes(ctypes)
        self.heap_type = None
        self.walker_class = callable()
        self.heap_validation_depth = 1
        raise NotImplementedError(
            'Please fix your self.heap_type and self.walker_class')

    def is_heap(self, mappings, mapping):
        """test if a mapping is a heap"""
        from haystack.mappings import base
        if not isinstance(mappings, base.Mappings):
            raise TypeError('Feed me a Mappings object')
        heap = self.read_heap(mapping)
        load = heap.loadMembers(mappings, self.heap_validation_depth)
        log.debug('HeapFinder.is_heap %s %s' % (mapping, load))
        return load

    def read_heap(self, mapping):
        """ return a ctypes heap struct mapped at address on the mapping"""
        addr = mapping.start
        heap = mapping.readStruct(addr, self.heap_type)
        return heap

    def get_heap_mappings(self, mappings):
        """return the list of heaps that load as heaps"""
        from haystack.mappings import base
        if not isinstance(mappings, base.Mappings):
            raise TypeError('Feed me a Mappings object')
        heap_mappings = []
        for mapping in mappings:
            # BUG: python-ptrace read /proc/$$/mem.
            # file.seek does not like long integers
            if mapping.pathname in ['[vdso]', '[vsyscall]']:
                log.debug('Ignore system mapping %s' % (mapping))
            elif self.is_heap(mappings, mapping):
                heap_mappings.append(mapping)
        heap_mappings.sort(key=lambda m: m.start)
        return heap_mappings

    def get_walker_for_heap(self, mappings, heap):
        return self.walker_class(mappings, heap, 0)
