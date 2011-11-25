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
  def get_a(self):
    print A._fields_
    return self.a
  
  def set_a(self, val):
    self.a = val
  
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
  def __init__(self):
    D.__init__(self)
    D.set_a(self, 1)
    C.__init__(self)
    C.set_a(self, 12)

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

e= E()

print [f for f in e.getFields()]

print dict(e.getFields())

#print D.set_a(e, 12)
#print C.set_a(e, 44)

print 'c:',C.get_a(e)
print 'd:',D.get_a(e)
##########


if __name__ == '__main__':
  printSizeof()

