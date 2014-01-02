# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-i386']
# POINTER_SIZE is: 4
#
import ctypes

print 'gen',ctypes


class struct_test3(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('val2', ctypes.c_uint32),
    ('me', ctypes.POINTER(ctypes.c_uint32)),
    ('val2b', ctypes.c_uint32),
    ('val1b', ctypes.c_uint32),
     ]

class struct_Node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('ptr2', ctypes.POINTER(None)),
     ]

__all__ = ['struct_Node', 'struct_test3']
