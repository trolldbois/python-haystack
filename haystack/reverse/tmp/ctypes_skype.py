#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

from haystack import model
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress
from haystack.model import LoadableMembers,RangeValue,NotNull,CString, IgnoreMember, PerfectMatch

log=logging.getLogger('ctypes_skype')


class SkypeStruct(LoadableMembers):
  ''' defines classRef '''
  pass


class Imp1(SkypeStruct):  # resolved:True SIG:i4P4u8P4 pointerResolved:False
  _fields_ = [
        ( 'small_int_0' , ctypes.c_uint ), #  1609
        ( 'ptr_4' , ctypes.c_void_p ), # @ ad66b88 [heap]
        ( 'untyped_8' , ctypes.c_ubyte * 8 ), #   else bytes:'\x00\xff\xff\xff\x01\x00\x00\x00'
        ( 'ptr_16' , ctypes.c_void_p ), # @ ad67608 [heap]
 ]
  expectedValues = {
  'small_int_0': RangeValue(0,36000),
  'ptr_4': NotNull,
  'untyped_8': PerfectMatch('\x00\xff\xff\xff\x01\x00\x00\x00'),
  'ptr_16': NotNull
  }

class Imp2(SkypeStruct):  # resolved:True SIG:i4P4u8P4 pointerResolved:False
  _fields_ = [
        ( 'check' , ctypes.c_ubyte * 8 ), #   else bytes:'\x00\xff\xff\xff\x01\x00\x00\x00'
 ]
  expectedValues = {
  'check': PerfectMatch('\x00\xff\xff\xff\x01\x00\x00\x00'),
  }
# 172622824
# 0xa4a03e8

model.registerModule(sys.modules[__name__])


