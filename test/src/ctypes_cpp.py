#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Expected testing allocators."""

from __future__ import print_function
import ctypes
import logging
import sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.utils import get_pointee_address, array2bytes, bytes2array
from haystack.constraints import LoadableMembers, RangeValue, NotNull, CString

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


log = logging.getLogger('cpp')


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


class E(D, C):
    _fields_ = [
        ('C', C),
        #('C', C),
        ('e', ctypes.c_uint)
    ]

################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
###model.copy_generated_classes(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################


############# Start expectedValues and methods overrides #################

# checkks

import sys
import inspect
src = sys.modules[__name__]


def printSizeof(mini=-1):
    for (name, klass) in inspect.getmembers(
            sys.modules[__name__], inspect.isclass):
        # and klass.__module__.endswith('%s_generated'%(__name__) ) :
        if isinstance(klass, type(ctypes.Structure)):
            if ctypes.sizeof(klass) > mini:
                print('%s:' % name, ctypes.sizeof(klass))

e = E()

e.a = 1
e.b = 2
e.c = 3
e.d = 4
e.e = 5

C.__setattr__(e, 'a', 99)
D.__setattr__(e, 'a', 66)
e.C.a = 122

# for f in e.getFields():
#  print f[0], getattr(e, f[0])

# print e.C.a

# print dict(e.getFields())

##########


if __name__ == '__main__':
    pass  # printSizeof()
