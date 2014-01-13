# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-x86_64']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes




class struct_a(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('a', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte),
    ('b', ctypes.c_uint16),
    ('c', ctypes.c_uint32),
    ('d', ctypes.c_uint64),
    ('e', ctypes.c_uint64),
    ('f', ctypes.c_float),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('g', ctypes.c_double),
    ('PADDING_2', ctypes.c_ubyte * 8),
    ('h', ctypes.c_longdouble),
     ]

class union_au(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('a', ctypes.c_ubyte),
    ('b', ctypes.c_uint16),
    ('c', ctypes.c_uint32),
    ('d', ctypes.c_uint64),
    ('e', ctypes.c_uint64),
    ('f', ctypes.c_float),
    ('g', ctypes.c_double),
    ('h', ctypes.c_longdouble),
     ]

class union_b(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('a', ctypes.c_byte),
    ('b', ctypes.c_int16),
    ('c', ctypes.c_int32),
    ('d', ctypes.c_int64),
    ('e', ctypes.c_int64),
    ('f', ctypes.c_ubyte),
    ('g', ctypes.c_byte),
    ('PADDING_0', ctypes.c_ubyte * 7),
     ]

class struct_c(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('a1', ctypes.c_uint32),
    ('b1', ctypes.c_uint8, 4),
    ('c1', ctypes.c_uint16, 10),
    ('d1', ctypes.c_uint16, 2),
    ('a2', ctypes.c_byte),
    ('b2', ctypes.c_uint8, 4),
    ('PADDING_0', ctypes.c_uint8, 4),
    ('c2', ctypes.c_uint16, 10),
    ('d2', ctypes.c_uint32, 2),
    ('PADDING_1', ctypes.c_uint32, 20),
    ('h', ctypes.c_int32),
     ]

class struct_d(ctypes.Structure):
    pass

struct_d._pack_ = True # source:False
struct_d._fields_ = [
    ('a', ctypes.POINTER(None)),
    ('b', ctypes.POINTER(struct_a)),
    ('b2', ctypes.POINTER(union_au)),
    ('PADDING_0', ctypes.c_ubyte * 8),
    ('c', struct_a * 10),
    ('c2', union_au * 10),
    ('c3', ctypes.POINTER(union_au) * 10),
    ('d', ctypes.POINTER(struct_d)),
    ('e', ctypes.POINTER(ctypes.c_int32)),
    ('f', ctypes.c_int32 * 10),
    ('f2', ctypes.POINTER(ctypes.c_int32) * 10),
    ('g', ctypes.c_byte),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('h', ctypes.POINTER(ctypes.c_byte)),
    ('i', ctypes.c_byte * 32),
    ('j', ctypes.POINTER(ctypes.c_byte) * 40),
    ('PADDING_2', ctypes.c_ubyte * 8),
]

__all__ = ['struct_c', 'struct_a', 'struct_d', 'union_b', 'union_au']
