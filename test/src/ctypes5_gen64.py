# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-linux']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 8:
    POINTER_T = ctypes.POINTER
else:
    # required to access _ctypes
    import _ctypes
    # Emulate a pointer class using the approriate c_int32/c_int64 type
    # The new class should have :
    # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
    # but the class should be submitted to a unique instance for each base type
    # to that if A == B, POINTER_T(A) == POINTER_T(B)
    ctypes._pointer_t_type_cache = {}
    def POINTER_T(pointee):
        # a pointer should have the same length as LONG
        fake_ptr_base_type = ctypes.c_uint64 
        # specific case for c_void_p
        if pointee is None: # VOID pointer type. c_void_p.
            pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
            clsname = 'c_void'
        else:
            clsname = pointee.__name__
        if clsname in ctypes._pointer_t_type_cache:
            return ctypes._pointer_t_type_cache[clsname]
        # make template
        class _T(_ctypes._SimpleCData,):
            _type_ = 'L'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(8, clsname), (_T,),{}) 
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class



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
    ('h', c_long_double_t),
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
    ('h', c_long_double_t),
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
    ('g', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 7),
     ]

class struct_c(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('a1', ctypes.c_uint32),
    ('b1', ctypes.c_uint32, 4),
    ('c1', ctypes.c_uint32, 10),
    ('d1', ctypes.c_uint32, 2),
    ('a2', ctypes.c_uint32, 8),
    ('b2', ctypes.c_uint32, 4),
    ('PADDING_0', ctypes.c_uint32, 4),
    ('c2', ctypes.c_uint32, 10),
    ('d2', ctypes.c_uint32, 2),
    ('PADDING_1', ctypes.c_uint32, 20),
    ('h', ctypes.c_int32),
     ]

class struct_d(ctypes.Structure):
    pass

struct_d._pack_ = True # source:False
struct_d._fields_ = [
    ('a', POINTER_T(None)),
    ('b', POINTER_T(struct_a)),
    ('b2', POINTER_T(union_au)),
    ('PADDING_0', ctypes.c_ubyte * 8),
    ('c', struct_a * 10),
    ('c2', union_au * 10),
    ('c3', POINTER_T(union_au) * 10),
    ('d', POINTER_T(struct_d)),
    ('e', POINTER_T(ctypes.c_int32)),
    ('f', ctypes.c_int32 * 10),
    ('f2', POINTER_T(ctypes.c_int32) * 10),
    ('g', ctypes.c_char),
    ('PADDING_1', ctypes.c_ubyte * 7),
    ('h', POINTER_T(ctypes.c_char)),
    ('i', ctypes.c_char * 32),
    ('j', POINTER_T(ctypes.c_char) * 40),
    ('PADDING_2', ctypes.c_ubyte * 8),
]

__all__ = \
    ['struct_c', 'struct_a', 'struct_d', 'union_b', 'union_au']
