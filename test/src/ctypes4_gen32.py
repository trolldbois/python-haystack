# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-i386']
# POINTER_SIZE is: 4
#
import ctypes




class class_cB(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('b', ctypes.c_uint32),
     ]

__all__ = ['class_cB']
