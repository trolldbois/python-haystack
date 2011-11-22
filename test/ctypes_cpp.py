#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging, sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

log=logging.getLogger('cpp')


# ============== Internal type defs ==============


class CPP(LoadableMembers):
  ''' defines classRef '''
  pass

class A(CPP):
  _fields_ = [
    ('a', ctypes.c_uint)
  ]
  
class B(A):
  _fields_ = [
    ('b', ctypes.c_uint)
  ]

class C(B):
  _fields_ = [
    ('c', ctypes.c_uint)
  ]

class D(B):
  _fields_ = [
    ('d', ctypes.c_uint)
  ]

class E(D,C):
  _fields_ = [
    ('e', ctypes.c_uint)
  ]

################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
###model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################


############# Start expectedValues and methods overrides #################

# checkks

import sys,inspect
src=sys.modules[__name__]


def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure):# and klass.__module__.endswith('%s_generated'%(__name__) ) :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)

##########


if __name__ == '__main__':
  printSizeof()

