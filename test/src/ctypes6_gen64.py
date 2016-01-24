# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-linux']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


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



class struct_entry(ctypes.Structure):
    pass

struct_entry._pack_ = True # source:False
struct_entry._fields_ = [
    ('flink', POINTER_T(struct_entry)),
    ('blink', POINTER_T(struct_entry)),
]

Entry = struct_entry
class struct_slist(ctypes.Structure):
    pass

struct_slist._pack_ = True # source:False
struct_slist._fields_ = [
    ('next', POINTER_T(struct_slist)),
]

SList = struct_slist
class struct_single_node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('entry', SList),
     ]

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
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('list', Entry),
    ('val2', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
     ]

class struct_Root(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ptr_to_double_list', POINTER_T(struct_Node)),
    ('ptr_to_single_node', POINTER_T(struct_single_node)),
    ('val2', ctypes.c_uint32),
    ('PADDING_1', ctypes.c_ubyte * 4),
     ]

__all__ = \
    ['struct_Node', 'struct_entry', 'struct_single_node',
    'struct_Root', 'struct_usual', 'SList', 'struct_slist', 'Entry']
