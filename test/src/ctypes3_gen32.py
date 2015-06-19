# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'i386-linux']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes


# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 4:
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
        fake_ptr_base_type = ctypes.c_uint32 
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
            _type_ = 'I'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(4, clsname), (_T,),{}) 
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class

c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 12:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*12



class struct_test3(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('val2', ctypes.c_uint32),
    ('me', POINTER_T(ctypes.c_uint32)),
    ('val2b', ctypes.c_uint32),
    ('val1b', ctypes.c_uint32),
     ]

class struct_Node(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val1', ctypes.c_uint32),
    ('ptr2', POINTER_T(None)),
     ]

__all__ = \
    ['struct_Node', 'struct_test3']
