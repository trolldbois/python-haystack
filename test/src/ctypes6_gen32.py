# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'linux-i386']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes




class struct_entry(ctypes.Structure):
    pass

struct_entry._pack_ = True # source:False
struct_entry._fields_ = [
    ('flink', ctypes.POINTER(struct_entry)),
    ('blink', ctypes.POINTER(struct_entry)),
]

Entry = struct_entry

class struct_usual(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('val2', ctypes.c_uint32),
    ('root', Entry),
    ('txt', ctypes.c_char * 128),
    ('val2b', ctypes.c_uint32),
    ('val1b', ctypes.c_uint32),
     ]

class struct_Node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('list', Entry),
    ('val2', ctypes.c_uint32),
     ]

__all__ = ['Entry', 'struct_entry', 'struct_usual', 'struct_Node']
