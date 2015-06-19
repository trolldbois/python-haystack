# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-linux']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes




class class_cA(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('_m1', ctypes.c_int32),
    ('_x', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
    ('a', ctypes.c_int32),
    ('p', ctypes.c_char * 5),
    ('PADDING_1', ctypes.c_ubyte * 3),
     ]

class class_cB(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 20),
    ('b', ctypes.c_uint32),
     ]

__all__ = \
    ['class_cB', 'class_cA']
