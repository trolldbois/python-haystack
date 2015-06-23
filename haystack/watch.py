#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Search for a known structure type in a process memory. """

import logging
import os
import sys
import time

from haystack import abouchet
from haystack import memory_mapper


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('watch')


def clear():
    print chr(27) + "[2J"


def check_varname_for_type(varname, structType):
    done = []
    st = structType
    from haystack import model
    import ctypes
    for v in varname:
        if not hasattr(st, v):
            fields = ["%s: %s" % (n, t) for n, t in st.getFields()]
            log.error(
                '(%s.)%s does not exists in type %s\n\t%s' %
                ('.'.join(done), v, st, '\n\t'.join(fields)))
            return False
        st = st.getFieldType(v)
        if ctypes.is_pointer_type(st):  # accept pointers
            st = model.get_subtype(st)
        done.append(v)
    return True


def get_varname_value(varname, instance):
    done = []
    var = instance
    for v in varname:
        var = getattr(var, v)
        done.append(v)
    return '%s = \n%s' % ('.'.join(done), var)


def watch(opt):
    ''' structname watch vaddr [refreshrate] [varname]'''
    addr = opt.addr
    refresh = opt.refresh_rate
    varname = opt.varname
    # get structure class
    structType = abouchet.getKlass(opt.structName)
    # verify target compliance
    if varname is not None:
        varname = varname.split('.')
        if not check_varname_for_type(varname, structType):
            return False
    # load the struct
    mappings = memory_mapper.MemoryMapper(opt).getMappings()
    finder = abouchet.StructFinder(mappings)
    # get the target memory map
    memoryMap = finder.mappings.is_valid_address_value(addr)
    if not memoryMap:
        log.error("the address is not accessible in the memoryMap")
        raise ValueError("the address is not accessible in the memoryMap")
    instance, validated = finder.loadAt(memoryMap, addr, structType)
    # instance.loadMembers(mappings)

    pyObj = instance.toPyObject()
    # print pyObj
    # print as asked every n secs.
    while True:
        clear()
        if varname is None:
            print pyObj
        else:
            print get_varname_value(varname, pyObj)

        if refresh == 0:
            break
        time.sleep(refresh)
        instance, validated = finder.loadAt(memoryMap, addr, structType)
        pyObj = instance.toPyObject()
