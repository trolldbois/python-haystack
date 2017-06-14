#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

from past.builtins import long
import ctypes
import logging
import struct
from struct import pack

import os

from haystack.abc import interfaces
from haystack import types

"""This module holds several useful function helpers"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

# never use ctypes import

log = logging.getLogger('utils')


class Utils(interfaces.ICTypesUtils):

    def __init__(self, _target_ctypes):
        self._ctypes = _target_ctypes
        assert isinstance(_target_ctypes, types.CTypesProxy)
        self.__local_process_memory_handler = None

    def formatAddress(self, addr):
        if self._ctypes.sizeof(self._ctypes.c_void_p) == 8:
            return '0x%016x' % addr
        else:
            return '0x%08x' % addr

    def unpackWord(self, bytes, endianess='@'):
        if self._ctypes.sizeof(self._ctypes.c_void_p) == 8:
            return struct.unpack('%sQ' % endianess, bytes)[0]
        else:
            return struct.unpack('%sI' % endianess, bytes)[0]

    def is_address_local(self, obj, structType=None):
        """
        Costly , checks if obj is mapped to local memory space.
        Returns the memory mapping if found.
        False, otherwise.
        """
        addr = self.get_pointee_address(obj)
        log.debug('get_pointee_address returned %x',addr)
        if addr == 0:
            return False
        # maintain a cache to improve performance.
        # if not found in cache, try to reload local process memory space.
        # the pointer memory space could have been allocated recently.
        # the calling function is most certainly going to fail anyway
        if self.__local_process_memory_handler is not None:
            ret = self.__local_process_memory_handler.is_valid_address(obj, structType)
            if ret:
                return ret
        # loading dependencies
        from haystack.mappings.process import make_local_memory_handler
        memory_handler = make_local_memory_handler()
        self.__local_process_memory_handler = memory_handler
        return self.__local_process_memory_handler.is_valid_address(obj, structType)

    def get_pointee_address(self, obj):
        """
        Returns the address of the struct pointed by the obj, or null if invalid.

        :param obj: a pointer.
        """
        # check for homebrew POINTER
        if hasattr(obj, '_sub_addr_'):
            if callable(obj._sub_addr_):
                log.debug('obj._sub_addr_: 0x%x', obj._sub_addr_())
                return obj._sub_addr_()
            log.debug('obj._sub_addr_: 0x%x', obj._sub_addr_)
            return obj._sub_addr_
        elif isinstance(obj, int) or isinstance(obj, long):
            # basictype pointers are created as int.
            return obj
        elif not bool(obj):
            return 0
        elif self._ctypes.is_function_type(type(obj)):
            return self._ctypes.cast(obj, self._ctypes.c_void_p).value
        elif self._ctypes.is_pointer_type(type(obj)):
            return self._ctypes.cast(obj, self._ctypes.c_void_p).value
            # check for null pointers
            # if bool(obj):
            # FIXME unreachable
            if not hasattr(obj, 'contents'):
                return 0
            # print '** NOT MY HAYSTACK POINTER'
            return self.__ctypes.addressof(obj.contents)
        else:
            return 0

    def container_of(self, memberaddr, typ, membername):
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
        return typ.from_address(memberaddr - self.offsetof(typ, membername))

    def offsetof(self, typ, membername):
        """
        Returns the offset of a member in a structure.

        :param typ: the structure type.
        :param membername: the membername in that structure.
        """
        return getattr(typ, membername).offset

    def ctypes_to_python_array(self, array):
        """Converts an array of undetermined Basic self.__ctypes class to a python array,
        by guessing it's type from it's class name.

        This is a bad example of introspection.
        """
        if isinstance(array, str) or isinstance(array, bytes):
            # special case for c_char[]
            return array
        if not self._ctypes.is_array_of_basic_instance(array):
            raise TypeError('NOT-AN-Basic-Type-ARRAY')
        if array._type_ in [self._ctypes.c_int, self._ctypes.c_uint, self._ctypes.c_long,
                            self._ctypes.c_ulong, self._ctypes.c_ubyte, self._ctypes.c_byte]:
            return [long(el) for el in array]
        if array._type_ in [self._ctypes.c_float, self._ctypes.c_double, self._ctypes.c_longdouble]:
            return [float(el) for el in array]
        sb = ''.join([struct.pack(array._type_._type_, el) for el in array])
        return sb

    def array2bytes(self, array):
        """Converts an array of undetermined Basic self.__ctypes class to a byte string,
        by guessing it's type from it's class name.

        This is a bad example of introspection.
        """
        if isinstance(array, str) or isinstance(array, bytes):
            # special case for c_char[]
            return array
        if self._ctypes.is_array_of_basic_instance(array):
            sb = b''.join([struct.pack(array._type_._type_, el) for el in array])
            return sb
        else:
            c_size = self._ctypes.sizeof(array)
            a2 = (self._ctypes.c_ubyte * c_size).from_address(self._ctypes.addressof(array))
            sb = b''.join([struct.pack('B', el) for el in a2])
            return sb

    def bytes2array(self, bytes, typ):
        """
        Converts a bytestring in a self.__ctypes array of typ() elements.

        :param bytes: str
        :param typ: ctypes
        :return: array
        """
        typLen = self._ctypes.sizeof(typ)
        if len(bytes) % typLen != 0:
            raise ValueError('thoses bytes are not an array of %s' % (typ))
        arrayLen = len(bytes) // typLen
        array = (typ * arrayLen)()
        if arrayLen == 0:
            return array
        fmt = self._ctypes.get_pack_format()[typ.__name__]
        try:
            for i in range(0, arrayLen):
                array[i] = struct.unpack(
                    fmt, bytes[typLen * i:typLen * (i + 1)])[0]
        except struct.error as e:
            log.error('format:%s typLen*i:typLen*(i+1) = %d:%d' %
                      (fmt, typLen * i, typLen * (i + 1)))
            raise e
        return array

    def pointer2bytes(self, attr, nb_element):
        """
        Returns an array from a self.__ctypes POINTER, given the number of elements.

        :param attr: the structure member.
        :param nb_element: the number of element in the array.
        """
        # attr is a pointer and we want to read elementSize of type(attr.contents))
        ## DEBUG statement
        # if not self.is_address_local(attr):
        #    raise TypeError('POINTER NOT LOCAL: %x', attr)
        first_element_addr = self.get_pointee_address(attr)
        array = (type(attr.contents) * nb_element).from_address(first_element_addr)
        # we have an array type starting at attr.contents[0]
        return self.array2bytes(array)

    def get_subtype(self, cls):
        """get the subtype of a pointer, array or basic type with haystack quirks."""
        # could use _pointer_type_cache
        if hasattr(cls, '_subtype_'):
            return cls._subtype_
        return cls._type_

    def get_word_size(self):
        return self._ctypes.sizeof(self._ctypes.c_void_p)

try:
    # Python 2
    py_xrange = xrange
    def xrange(start, end, step=1):
        """ stoupid xrange can't handle long ints... """
        end = end - start
        for val in py_xrange(0, end, step):
            yield start + val
        return
except NameError as e:
    # Python 3
    xrange = range


def bytes2array(bytes, typ):
    """
    Converts a bytestring in a ctypes array of typ() elements.

    :param bytes: str
    :param typ: ctypes
    :return: array
    """
    typLen = ctypes.sizeof(typ)
    if len(bytes) % typLen != 0:
        raise ValueError('thoses bytes are not an array of %s' % (typ))
    arrayLen = len(bytes) // typLen
    array = (typ * arrayLen)()
    if arrayLen == 0:
        return array
    fmt = typ._type_
    try:
        for i in range(0, arrayLen):
            array[i] = struct.unpack(
                fmt, bytes[typLen * i:typLen * (i + 1)])[0]
    except struct.error as e:
        log.error('format:%s typLen*i:typLen*(i+1) = %d:%d' %
                  (fmt, typLen * i, typLen * (i + 1)))
        raise e
    return array
