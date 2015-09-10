# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'i386-win']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 12:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*12

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



int8_t = ctypes.c_int8
int16_t = ctypes.c_int16
int32_t = ctypes.c_int32
int64_t = ctypes.c_int64
uint8_t = ctypes.c_uint8
uint16_t = ctypes.c_uint16
uint32_t = ctypes.c_uint32
uint64_t = ctypes.c_uint64
int_least8_t = ctypes.c_byte
int_least16_t = ctypes.c_int16
int_least32_t = ctypes.c_int32
int_least64_t = ctypes.c_int64
uint_least8_t = ctypes.c_ubyte
uint_least16_t = ctypes.c_uint16
uint_least32_t = ctypes.c_uint32
uint_least64_t = ctypes.c_uint64
int_fast8_t = ctypes.c_byte
int_fast16_t = ctypes.c_int32
int_fast32_t = ctypes.c_int32
int_fast64_t = ctypes.c_int64
uint_fast8_t = ctypes.c_ubyte
uint_fast16_t = ctypes.c_uint32
uint_fast32_t = ctypes.c_uint32
uint_fast64_t = ctypes.c_uint64
intptr_t = ctypes.c_int32
uintptr_t = ctypes.c_uint32
intmax_t = ctypes.c_int64
uintmax_t = ctypes.c_uint64
UINT8 = ctypes.c_ubyte
UCHAR = ctypes.c_ubyte
BOOL = ctypes.c_ubyte
CHAR = ctypes.c_byte
INT8 = ctypes.c_byte
WCHAR = ctypes.c_uint16
UINT16 = ctypes.c_uint16
USHORT = ctypes.c_uint16
SHORT = ctypes.c_int16
UINT32 = ctypes.c_uint32
ULONG = ctypes.c_uint32
LONG = ctypes.c_int32
UINT64 = ctypes.c_uint64
ULONGLONG = ctypes.c_uint64
LONGLONG = ctypes.c_int64
PPVOID64 = ctypes.c_uint64
PVOID64 = ctypes.c_uint64
PVOID32 = ctypes.c_uint32
PPVOID32 = ctypes.c_uint32
VOID = None
DOUBLE = ctypes.c_double
PUINT8 = POINTER_T(ctypes.c_ubyte)
PUCHAR = POINTER_T(ctypes.c_ubyte)
PBOOL = POINTER_T(ctypes.c_ubyte)
PCHAR = POINTER_T(ctypes.c_byte)
PINT8 = POINTER_T(ctypes.c_byte)
PUINT16 = POINTER_T(ctypes.c_uint16)
PUSHORT = POINTER_T(ctypes.c_uint16)
PSHORT = POINTER_T(ctypes.c_int16)
PUINT32 = POINTER_T(ctypes.c_uint32)
PULONG = POINTER_T(ctypes.c_uint32)
PLONG = POINTER_T(ctypes.c_int32)
PUINT64 = POINTER_T(ctypes.c_uint64)
PULONGLONG = POINTER_T(ctypes.c_uint64)
PLONGLONG = POINTER_T(ctypes.c_int64)
PPVOID = POINTER_T(POINTER_T(None))
PVOID = POINTER_T(None)

class union__LARGE_INTEGER(ctypes.Union):
    pass

class struct_c__U__LARGE_INTEGER_Sa_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('LowPart', ctypes.c_uint32),
    ('HighPart', ctypes.c_int32),
     ]

class struct_c__U__LARGE_INTEGER_Sa_2(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('QuadPart', ctypes.c_int64),
     ]

class struct_c__U__LARGE_INTEGER_S_WinXPSP3X86DOT32DOTh_5312(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('LowPart', ctypes.c_uint32),
    ('HighPart', ctypes.c_int32),
     ]

union__LARGE_INTEGER._pack_ = True # source:True
union__LARGE_INTEGER._fields_ = [
    ('_0', struct_c__U__LARGE_INTEGER_Sa_0),
    ('u', struct_c__U__LARGE_INTEGER_S_WinXPSP3X86DOT32DOTh_5312),
    ('_2', struct_c__U__LARGE_INTEGER_Sa_2),
]

LARGE_INTEGER = union__LARGE_INTEGER
class union__ULARGE_INTEGER(ctypes.Union):
    pass

class struct_c__U__ULARGE_INTEGER_Sa_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('LowPart', ctypes.c_uint32),
    ('HighPart', ctypes.c_uint32),
     ]

class struct_c__U__ULARGE_INTEGER_Sa_2(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('QuadPart', ctypes.c_uint64),
     ]

class struct_c__U__ULARGE_INTEGER_S_WinXPSP3X86DOT32DOTh_5555(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('LowPart', ctypes.c_uint32),
    ('HighPart', ctypes.c_uint32),
     ]

union__ULARGE_INTEGER._pack_ = True # source:True
union__ULARGE_INTEGER._fields_ = [
    ('_0', struct_c__U__ULARGE_INTEGER_Sa_0),
    ('u', struct_c__U__ULARGE_INTEGER_S_WinXPSP3X86DOT32DOTh_5555),
    ('_2', struct_c__U__ULARGE_INTEGER_Sa_2),
]

ULARGE_INTEGER = union__ULARGE_INTEGER

class struct__UNICODE_STRING(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Length', ctypes.c_uint16),
    ('MaximumLength', ctypes.c_uint16),
    ('Buffer', POINTER_T(ctypes.c_uint16)),
     ]

UNICODE_STRING = struct__UNICODE_STRING
PUNICODE_STRING = POINTER_T(struct__UNICODE_STRING)
PPUNICODE_STRING = POINTER_T(POINTER_T(struct__UNICODE_STRING))


class struct__PEB(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('InheritedAddressSpace', ctypes.c_ubyte),
    ('ReadImageFileExecOptions', ctypes.c_ubyte),
    ('BeingDebugged', ctypes.c_ubyte),
    ('SpareBool', ctypes.c_ubyte),
    ('Mutant', POINTER_T(None)),
    ('ImageBaseAddress', POINTER_T(None)),
    ('Ldr', POINTER_T(None)),
    ('ProcessParameters', POINTER_T(None)),
    ('SubSystemData', POINTER_T(None)),
    ('ProcessHeap', POINTER_T(None)),
    ('FastPebLock', POINTER_T(None)),
    ('FastPebLockRoutine', POINTER_T(None)),
    ('FastPebUnlockRoutine', POINTER_T(None)),
    ('EnvironmentUpdateCount', ctypes.c_uint32),
    ('KernelCallbackTable', POINTER_T(None)),
    ('SystemReserved', ctypes.c_uint32 * 1),
    ('AtlThunkSListPtr32', ctypes.c_uint32),
    ('FreeList', POINTER_T(None)),
    ('TlsExpansionCounter', ctypes.c_uint32),
    ('TlsBitmap', POINTER_T(None)),
    ('TlsBitmapBits', ctypes.c_uint32 * 2),
    ('ReadOnlySharedMemoryBase', POINTER_T(None)),
    ('ReadOnlySharedMemoryHeap', POINTER_T(None)),
    ('ReadOnlyStaticServerData', POINTER_T(POINTER_T(None))),
    ('AnsiCodePageData', POINTER_T(None)),
    ('OemCodePageData', POINTER_T(None)),
    ('UnicodeCaseTableData', POINTER_T(None)),
    ('NumberOfProcessors', ctypes.c_uint32),
    ('NtGlobalFlag', ctypes.c_uint32),
    ('gap_in_pdb_ofs_6C', ctypes.c_ubyte * 4),
    ('CriticalSectionTimeout', LARGE_INTEGER),
    ('HeapSegmentReserve', ctypes.c_uint32),
    ('HeapSegmentCommit', ctypes.c_uint32),
    ('HeapDeCommitTotalFreeThreshold', ctypes.c_uint32),
    ('HeapDeCommitFreeBlockThreshold', ctypes.c_uint32),
    ('NumberOfHeaps', ctypes.c_uint32),
    ('MaximumNumberOfHeaps', ctypes.c_uint32),
    ('ProcessHeaps', POINTER_T(POINTER_T(None))),
    ('GdiSharedHandleTable', POINTER_T(None)),
    ('ProcessStarterHelper', POINTER_T(None)),
    ('GdiDCAttributeList', ctypes.c_uint32),
    ('LoaderLock', POINTER_T(None)),
    ('OSMajorVersion', ctypes.c_uint32),
    ('OSMinorVersion', ctypes.c_uint32),
    ('OSBuildNumber', ctypes.c_uint16),
    ('OSCSDVersion', ctypes.c_uint16),
    ('OSPlatformId', ctypes.c_uint32),
    ('ImageSubsystem', ctypes.c_uint32),
    ('ImageSubsystemMajorVersion', ctypes.c_uint32),
    ('ImageSubsystemMinorVersion', ctypes.c_uint32),
    ('ImageProcessAffinityMask', ctypes.c_uint32),
    ('GdiHandleBuffer', ctypes.c_uint32 * 34),
    ('PostProcessInitRoutine', POINTER_T(ctypes.CFUNCTYPE(None))),
    ('TlsExpansionBitmap', POINTER_T(None)),
    ('TlsExpansionBitmapBits', ctypes.c_uint32 * 32),
    ('SessionId', ctypes.c_uint32),
    ('AppCompatFlags', ULARGE_INTEGER),
    ('AppCompatFlagsUser', ULARGE_INTEGER),
    ('pShimData', POINTER_T(None)),
    ('AppCompatInfo', POINTER_T(None)),
    ('CSDVersion', UNICODE_STRING),
    ('ActivationContextData', POINTER_T(None)),
    ('ProcessAssemblyStorageMap', POINTER_T(None)),
    ('SystemDefaultActivationContextData', POINTER_T(None)),
    ('SystemAssemblyStorageMap', POINTER_T(None)),
    ('MinimumStackCommit', ctypes.c_uint32),
    ('gap_in_pdb_ofs_20C', ctypes.c_ubyte * 4),
    ]

