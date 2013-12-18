# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# POINTER_SIZE is: 8
#
import ctypes
import sys

from haystack import model
from haystack.model import RangeValue,NotNull,CString, IgnoreMember

from test.src import ctypes3_gen

model.copyGeneratedClasses(ctypes3_gen, sys.modules[__name__])
# register all classes to haystack
# create plain old python object from ctypes.Structure's, to pickle them
model.registerModule(sys.modules[__name__])

struct_test3.expectedValues={
    "val1" : [0xdeadbeef],
    "val1b" : [0xdeadbeef],
    "val2" : [0x10101010],
    "val2b" : [0x10101010],
    }

struct_Node.expectedValues={
    "val1": [0xdeadbeef],
    "ptr2": [NotNull],
    }




