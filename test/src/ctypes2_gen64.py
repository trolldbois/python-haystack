# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-linux']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


class struct_sA(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('a', ctypes.c_int32),
    ]


class struct_sB(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 4),
        ('b', ctypes.c_uint32),
    ]


class struct_sC(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 8),
        ('c', ctypes.c_uint32),
    ]


class struct_sD(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 8),
        ('d', ctypes.c_uint32),
    ]


class class_cA(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('a', ctypes.c_int32),
    ]


class class_cB(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 4),
        ('b', ctypes.c_uint32),
    ]


class class_cC(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 8),
        ('c', ctypes.c_uint32),
    ]


class class_cD(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 8),
        ('d', ctypes.c_uint32),
    ]


class class_cE(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('PADDING_0', ctypes.c_ubyte * 24),
        ('e', ctypes.c_uint32),
    ]

__all__ = \
    ['class_cA', 'class_cB', 'class_cD', 'class_cC', 'struct_sB',
     'struct_sC', 'struct_sA', 'struct_sD', 'class_cE']
