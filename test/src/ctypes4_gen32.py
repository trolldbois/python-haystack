# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-i386']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes




class class_cB(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('b', ctypes.c_uint32),
     ]

__all__ = ['class_cB']
