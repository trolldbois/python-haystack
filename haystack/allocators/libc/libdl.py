#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

from __future__ import print_function
import ctypes
import logging

import os
import pickle

from haystack.mappings.process import make_process_memory_handler

log = logging.getLogger('libdl')


class Dl_info(ctypes.Structure):
    _fields_ = [
        # Pathname of shared object that contains address
        ('dli_fname', ctypes.c_char_p),
        # Address at which shared object is loaded
        ('dli_fbase', ctypes.c_void_p),
        # Name of nearest symbol with address lower than addr
        ('dli_sname', ctypes.c_char_p),
        # Exact address of symbol named in dli_sname
        ('dli_saddr', ctypes.c_void_p)
    ]


class Dummy():
    pass


def getMappings():
    me = Dummy()
    me.pid = os.getpid()
    return make_process_memory_handler(me)

# TODO FIXME: make a non-batch version


def reverseLocalFonctionPointerNames(context):
    """
    reverse fn pointer names by trying to rebase the ptr value to a local ld_open.

    load local memdump
    map all librairies
    go through all pointers in librairies
    try to dl_addr the pointers by rebasing.
    :param context:
    :return:
    """
    fsave = context.config.getCacheFilename(
        context.config.CACHE_FUNCTION_NAMES,
        context.dumpname)
    if os.access(fsave, os.F_OK):
        vtable = pickle.load(file(fsave, 'rb'))
        for x in vtable.items():
            yield x
        raise StopIteration

    IGNORES = ['None', '[heap]', '[stack]', '[vdso]']

    # XXX this is not portable.
    libdl = ctypes.CDLL('libdl.so')

    def getname(fnaddr):
        info = Dl_info()
        ret = libdl.dladdr(fnaddr, ctypes.byref(info))
        return info.dli_sname.string, info.dli_saddr

    mappings = context.mappings
    ldso = dict()
    for m in mappings:
        if m.pathname not in IGNORES and m.pathname not in ldso:
            try:
                ldso[m.pathname] = ctypes.CDLL(m.pathname)
            except OSError as e:
                IGNORES.append(m.pathname)

    # looking in [heap] pointing to elsewhere
    all_ptrs = context.listPointerValueInHeap()
    log.debug('[+] %d pointers in heap to elsewhere ' % (len(all_ptrs)))

    localmappings = getMappings()
    vtable = dict()

    for ptr in set(all_ptrs):
        # get dump mmap
        m = mappings.get_mapping_for_address(ptr)
        if m.pathname not in IGNORES:
            # find the right localmmap
            localmaps = localmappings._get_mapping(m.pathname)
            found = False
            for localm in localmaps:
                if localm.offset == m.offset and localm.permissions == m.permissions:
                    # found it
                    found = True
                    caddr = ptr - m.start + localm.start  # rebase
                    dl_name, fnaddr = getname(caddr)
                    if dl_name is not None:
                        if fnaddr == caddr:  # reverse check
                            log.debug('[+] REBASE 0x%x -> 0x%x p:%s|%s|=%s  off:%x|%x|=%s %s fn: %s @%x' % (
                                ptr, caddr, m.permissions, localm.permissions, localm.permissions == m.permissions,
                                m.offset, localm.offset, m.offset == localm.offset, m.pathname, dl_name, fnaddr))
                            vtable[ptr] = dl_name
                            yield (ptr, dl_name)
                        else:
                            continue
                            print('[-] MIDDLE 0x%x -> 0x%x p:%s|%s|=%s  off:%x|%x|=%s %s fn: %s @%x' % (
                                ptr, caddr, m.permissions, localm.permissions, localm.permissions == m.permissions,
                                m.offset, localm.offset, m.offset == localm.offset, m.pathname, dl_name, fnaddr))
                    else:
                        continue
                        print('FAIL REBASE (not public ?) 0x%x -> 0x%x p:%s|%s|=%s  off:%x|%x|=%s  %s fn: %s ' % (
                            ptr, caddr, m.permissions, localm.permissions, localm.permissions == m.permissions,
                            m.offset, localm.offset, m.offset == localm.offset, m.pathname, dl_name))
                        pass
                    break
            if not found:
                continue
                print('[+] not a fn pointer %x\n' % (ptr), m, '\n   ---dump  Vs local ---- \n',
                      '\n'.join(map(str, localmaps)))
    # pass
    for name, lib in ldso.items():
        ret = libdl.dlclose(lib._handle)

    import pickle
    pickle.dump(vtable, file(fsave, 'wb'))

    raise StopIteration
