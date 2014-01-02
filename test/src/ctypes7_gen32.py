# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-i386']
# POINTER_SIZE is: 4
#
import ctypes




class struct_Node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('ptr2', ctypes.POINTER(None)),
     ]

__all__ = ['struct_Node']
