#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""This module holds several useful function helpers"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import os
import struct
from struct import pack
from struct import unpack 

# never import ctypes globally

log = logging.getLogger('utils')

def formatAddress(addr):
    import ctypes
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        return b'0x%016x' % addr
    else:
        return b'0x%08x' % addr

def unpackWord(bytes, endianess='@'):
    import ctypes
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        return struct.unpack('%sQ'%endianess, bytes)[0]
    else:
        return struct.unpack('%sI'%endianess, bytes)[0]

def is_address_local(obj, structType=None):
    """ 
    Costly , checks if obj is mapped to local memory space.
    Returns the memory mapping if found.
    False, otherwise.
    """
    addr = getaddress(obj)
    if addr == 0:
        return False
    class P:
        pid = os.getpid()
    from memory_mapping import readProcessMappings  # loading dependencies
    mappings = readProcessMappings(P()) # memory_mapping
    return is_valid_address(obj, mappings, structType)

def getaddress(obj):
    """ 
    Returns the address of the struct pointed by the obj, or null if invalid.

    :param obj: a pointer.
    """
    import ctypes
    # check for homebrew POINTER
    if hasattr(obj,'_sub_addr_'):
        #print 'obj._sub_addr_', hex(obj._sub_addr_)
        return obj._sub_addr_
    # check for null pointers
    if bool(obj):
        if not hasattr(obj,'contents'):
            return 0
        #print '** NOT MY HAYSTACK POINTER'
        return ctypes.addressof(obj.contents)
    else:
        return 0  

def container_of(memberaddr, typ, membername):
    """
    From a pointer to a member, returns the parent struct.
    Returns the instance of typ(), in which the member "membername' is really.
    Useful in some Kernel linked list which used members as prec,next pointers.

    :param memberadd: the address of membername.
    :param typ: the type of the containing structure.
    :param membername: the membername.

    Stolen from linux kernel headers.
         const typeof( ((typ *)0)->member ) *__mptr = (ptr);    
        (type *)( (char *)__mptr - offsetof(type,member) );}) 
    """
    return typ.from_address( memberaddr - offsetof(typ, membername) )

def offsetof(typ, membername):
    """
    Returns the offset of a member in a structure.

    :param typ: the structure type.
    :param membername: the membername in that structure.
    """
    return getattr(typ, membername).offset

def array2bytes(array):
    """Converts an array of undetermined Basic Ctypes class to a byte string, 
    by guessing it's type from it's class name.

    This is a bad example of introspection.
    """
    import ctypes
    if not ctypes.is_array_of_basic_instance(array):
        raise TypeError('NOT-AN-Basic-Type-ARRAY')
    sb = b''.join([pack(array._type_._type_, el) for el in array])
    return sb

def bytes2array(bytes, typ):
    """Converts a bytestring in a ctypes array of typ() elements."""
    import ctypes
    typLen = ctypes.sizeof(typ)
    if len(bytes)%typLen != 0:
        raise ValueError('thoses bytes are not an array of %s'%(typ))
    arrayLen = len(bytes)/typLen
    array = (typ*arrayLen)()
    if arrayLen == 0:
        return array
    fmt = ctypes.get_pack_format()[typ.__name__]
    import struct
    try:
        for i in range(0,arrayLen):
            array[i] = struct.unpack(fmt, bytes[typLen*i:typLen*(i+1)])[0]
    except struct.error,e:
        log.error('format:%s typLen*i:typLen*(i+1) = %d:%d'%(fmt, typLen*i,typLen*(i+1)))
        raise e
    return array


def pointer2bytes(attr,nbElement):
    """ 
    Returns an array from a ctypes POINTER, given the number of elements.

    :param attr: the structure member.
    :param nbElement: the number of element in the array.
    """
    # attr is a pointer and we want to read elementSize of type(attr.contents))
    if not is_address_local(attr):
        return 'POINTER NOT LOCAL'
    firstElementAddr = getaddress(attr)
    array = (type(attr.contents)*nbElement).from_address(firstElementAddr)
    # we have an array type starting at attr.contents[0]
    return array2bytes(array)


try:
    # Python 2
    py_xrange = xrange
    def xrange(start, end, step=1):
        """ stoupid xrange can't handle long ints... """
        end = end-start
        for val in py_xrange(0, end, step):
            yield start+val
        return
except NameError as e:
    # Python 3
    xrange = range

