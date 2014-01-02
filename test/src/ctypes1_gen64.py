# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-x86_64']
# POINTER_SIZE is: 8
#
import ctypes




class struct_Node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ptr2', ctypes.POINTER(None)),
     ]

__all__ = ['struct_Node']
