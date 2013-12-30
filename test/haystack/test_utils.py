#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

# init ctypes with a controlled type size
from haystack import model
from haystack import utils

import operator
import os
import struct
import unittest


import ctypes

def make_types():
    # make some structures.
    class St(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_int) ]
    class St2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_long) ]
    class SubSt2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_longlong) ]
    #
    btype = ctypes.c_int
    voidp = ctypes.c_void_p
    stp = ctypes.POINTER(St)
    stpvoid = ctypes.POINTER(None)
    arra1 = (ctypes.c_long *4)
    arra2 = (St *4)
    arra3 = (ctypes.POINTER(St) *4)
    charp = ctypes.c_char_p
    string = ctypes.CString
    fptr = type(ctypes.memmove)
    arra4 = (fptr*256)
    return locals()



if __name__ == '__main__':
    unittest.main(verbosity=0)


