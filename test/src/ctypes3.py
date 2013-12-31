# -*- coding: utf-8 -*-
#

import importlib
import sys

from haystack import model
from haystack.constraints import RangeValue,NotNull,IgnoreMember

# should now already be subverted to the target arch.
import ctypes
longbits = ctypes.sizeof(ctypes.c_long)*8

print '****', longbits, ctypes

# import target arch generated ctypes3 python module.
gen = importlib.import_module('test.src.ctypes3_gen%d'%(longbits)) 

print '****', longbits, gen


model.copyGeneratedClasses(gen, sys.modules[__name__])
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




