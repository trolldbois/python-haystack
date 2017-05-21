#!/usr/bin/env python

# minidump.py is licensed under The MIT License (MIT)
#
# Copyright (c) 2008 Brendan Dolan-Gavitt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import print_function

from datetime import datetime, timedelta
from time import mktime

from construct import *

from haystack.mappings import file


def Hex(base):
    return ExprAdapter(base,
                       lambda obj, ctx: int(obj, 16),
                       lambda obj, ctx: hex(obj),
                       )


class NullStringAdapter(Adapter):

    def _encode(self, obj, ctx):
        return obj

    def _decode(self, obj, ctx):
        return obj.split('\x00')[0]


class TimeDateAdapter(Adapter):

    def _encode(self, obj, ctx):
        return int(mktime(datetime.timetuple()))

    def _decode(self, obj, ctx):
        return datetime.fromtimestamp(obj)


class TimeDeltaAdapter(Adapter):

    def _encode(self, obj, ctx):
        seconds = (obj.days * 86400) + obj.seconds
        return seconds

    def _decode(self, obj, ctx):
        return timedelta(seconds=obj)


class WindowsTimeDateAdapter(Adapter):

    def _encode(self, obj, ctx):
        unix_time = int(mktime(datetime.timetuple()))
        if unix_time == 0:
            return unix_time

        windows_time = unix_time + 11644473600
        windows_time = windows_time * 10000000

        return windows_time

    def _decode(self, obj, ctx):
        unix_time = obj / 10000000

        if unix_time == 0:
            return datetime.fromtimestamp(obj)

        unix_time = unix_time - 11644473600

        if unix_time < 0:
            unix_time = 0

        return datetime.fromtimestamp(unix_time)


class WindowsTimeDeltaAdapter(Adapter):

    def _encode(self, obj, ctx):
        seconds = (obj.days * 86400) + obj.seconds
        return (seconds * 10000000) + (obj.microseconds * 10)

    def _decode(self, obj, ctx):
        seconds = (obj / 10000000)
        microseconds = (obj % 10000000) / 10
        return timedelta(seconds=seconds, microseconds=microseconds)

MINIDUMP_STREAM_TYPE = Enum(ULInt32('StreamType'),
                            UnusedStream=0,
                            ReservedStream0=1,
                            ReservedStream1=2,
                            ThreadListStream=3,           # SUPPORTED
                            ModuleListStream=4,           # SUPPORTED
                            MemoryListStream=5,           # SUPPORTED
                            ExceptionStream=6,            # SUPPORTED
                            SystemInfoStream=7,           # SUPPORTED
                            ThreadExListStream=8,         # UNTESTED
                            Memory64ListStream=9,         # SUPPORTED
                            CommentStreamA=10,            # SUPPORTED
                            CommentStreamW=11,            # SUPPORTED
                            HandleDataStream=12,          # SUPPORTED
                            FunctionTableStream=13,       # UNTESTED
                            UnloadedModuleListStream=14,  # SUPPORTED
                            MiscInfoStream=15,            # SUPPORTED
                            MemoryInfoListStream=16,      # SUPPORTED
                            ThreadInfoListStream=17,      # SUPPORTED
                            HandleOperationListStream=18,  # UNTESTED
                            LastReservedStream=0xffff,
                            WindowHandleInfoStream=0x10000,  # REV ENG
                            _default_=Pass,
                            )

MINIDUMP_TYPES = FlagsEnum(ULInt64("Flags"),
                           MiniDumpWithDataSegs=0x00000001,
                           MiniDumpWithFullMemory=0x00000002,
                           MiniDumpWithHandleData=0x00000004,
                           MiniDumpFilterMemory=0x00000008,
                           MiniDumpScanMemory=0x00000010,
                           MiniDumpWithUnloadedModules=0x00000020,
                           MiniDumpWithIndirectlyReferencedMemory=0x00000040,
                           MiniDumpFilterModulePaths=0x00000080,
                           MiniDumpWithProcessThreadData=0x00000100,
                           MiniDumpWithPrivateReadWriteMemory=0x00000200,
                           MiniDumpWithoutOptionalData=0x00000400,
                           MiniDumpWithFullMemoryInfo=0x00000800,
                           MiniDumpWithThreadInfo=0x00001000,
                           MiniDumpWithCodeSegs=0x00002000,
                           )


def MINIDUMP_LOCATION_DESCRIPTOR(name):
    return Struct(name,
                  ULInt32('DataSize'),
                  ULInt32('RVA'),
                  )


def MINIDUMP_MEMORY_DESCRIPTOR(name):
    return Struct(name,
                  ULInt64('StartOfMemoryRange'),
                  MINIDUMP_LOCATION_DESCRIPTOR('Memory'),
                  )


def MINIDUMP_STRING(name):
    return PascalString(
        name, length_field=ULInt32('length'), encoding='utf-16-le')


def VS_FIXEDFILEINFO(name):
    return Struct(name,
                  ULInt32('dwSignature'),
                  ULInt32('dwStrucVersion'),
                  ULInt32('dwFileVersionMS'),
                  ULInt32('dwFileVersionLS'),
                  ULInt32('dwProductVersionMS'),
                  ULInt32('dwProductVersionLS'),
                  ULInt32('dwFileFlagsMask'),
                  ULInt32('dwFileFlags'),
                  ULInt32('dwFileOS'),
                  ULInt32('dwFileType'),
                  ULInt32('dwFileSubtype'),
                  ULInt32('dwFileDateMS'),
                  ULInt32('dwFileDateLS'),
                  )


def NullPointer(pointer, pointed_to):
    """A Pointer that checks to see if it's null first"""
    return If(pointer,
              Pointer(pointer, pointed_to),
              )

# Thread stream
MAXIMUM_SUPPORTED_EXTENSION = 512
CONTEXT_FLAGS = FlagsEnum(ULInt32("ContextFlags"),
                          CONTEXT_i386=0x00010000,
                          CONTEXT_CONTROL=0x00010001,
                          CONTEXT_INTEGER=0x00010002,
                          CONTEXT_SEGMENTS=0x00010004,
                          CONTEXT_FLOATING_POINT=0x00010008,
                          CONTEXT_DEBUG_REGISTERS=0x00010010,
                          CONTEXT_EXTENDED_REGISTERS=0x00010020,
                          )

FLOATING_SAVE_AREA = Struct("FloatSave",
                            ULInt32('ControlWord'),
                            ULInt32('StatusWord'),
                            ULInt32('TagWord'),
                            ULInt32('ErrorOffset'),
                            ULInt32('ErrorSelector'),
                            ULInt32('DataOffset'),
                            ULInt32('DataSelector'),
                            HexDumpAdapter(Field("RegisterArea", 80)),
                            ULInt32('Cr0NpxState'),
                            )

CONTEXT = Struct('CONTEXT',
                 CONTEXT_FLAGS,
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_DEBUG_REGISTERS,
                    Embed(Struct("DebugRegisters",
                                 ULInt32('Dr0'),
                                 ULInt32('Dr1'),
                                 ULInt32('Dr2'),
                                 ULInt32('Dr3'),
                                 ULInt32('Dr6'),
                                 ULInt32('Dr7'),
                                 )),
                    ),
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_FLOATING_POINT,
                     FLOATING_SAVE_AREA,
                    ),
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_SEGMENTS,
                     Embed(Struct("SegmentRegisters",
                                  ULInt32('SegGs'),
                                  ULInt32('SegFs'),
                                  ULInt32('SegEs'),
                                  ULInt32('SegDs'),
                                  )),
                    ),
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_INTEGER,
                     Embed(Struct("IntegerRegisters",
                                  ULInt32('Edi'),
                                  ULInt32('Esi'),
                                  ULInt32('Ebx'),
                                  ULInt32('Edx'),
                                  ULInt32('Ecx'),
                                  ULInt32('Eax'),
                                  )),
                    ),
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_CONTROL,
                     Embed(Struct("ControlRegisters",
                                  ULInt32('Ebp'),
                                  ULInt32('Eip'),
                                  ULInt32('SegCs'),
                                  ULInt32('EFlags'),
                                  ULInt32('Esp'),
                                  ULInt32('SegSs'),
                                  )),
                    ),
                 If(lambda ctx: ctx.ContextFlags.CONTEXT_EXTENDED_REGISTERS,
                     HexDumpAdapter(
                         Field(
                             "ExtendedRegisters",
                             MAXIMUM_SUPPORTED_EXTENSION),
                     ),
                    ),
                 )

MINIDUMP_THREAD = Struct('MINIDUMP_THREAD',
                         ULInt32('ThreadId'),
                         ULInt32('SuspendCount'),
                         ULInt32('PriorityClass'),
                         ULInt32('Priority'),
                         ULInt64('Teb'),
                         MINIDUMP_MEMORY_DESCRIPTOR('Stack'),
                         MINIDUMP_LOCATION_DESCRIPTOR('ThreadContext'),
                         NullPointer(
                             lambda ctx: ctx.ThreadContext.RVA,
                             CONTEXT),
                         )

MINIDUMP_THREAD_LIST = Struct('MINIDUMP_THREAD_LIST',
                              ULInt32('NumberOfThreads'),
                              Array(lambda ctx: ctx.NumberOfThreads,
                                    MINIDUMP_THREAD,
                                    ),
                              )

# Thread info stream
THREAD_INFO_FLAGS = FlagsEnum(ULInt32("DumpFlags"),
                              ERROR_THREAD=0x00000001,
                              EXITED_THREAD=0x00000004,
                              WRITING_THREAD=0x00000002,
                              INVALID_INFO=0x00000008,
                              INVALID_CONTEXT=0x00000010,
                              INVALID_TEB=0x00000020,
                              )

MINIDUMP_THREAD_INFO = Struct('MINIDUMP_THREAD_INFO',
                              ULInt32('ThreadId'),
                              THREAD_INFO_FLAGS,
                              ULInt32('DumpError'),
                              ULInt32('ExitStatus'),
                              WindowsTimeDateAdapter(ULInt64('CreateTime')),
                              WindowsTimeDateAdapter(ULInt64('ExitTime')),
                              WindowsTimeDeltaAdapter(ULInt64('KernelTime')),
                              WindowsTimeDeltaAdapter(ULInt64('UserTime')),
                              ULInt64('StartAddress'),
                              ULInt64('Affinity'),
                              )

MINIDUMP_THREAD_INFO_LIST = Struct('MINIDUMP_THREAD_INFO_LIST',
                                   ULInt32('SizeOfHeader'),
                                   ULInt32('SizeOfEntry'),
                                   ULInt32('NumberOfEntries'),
                                   Array(lambda ctx: ctx.NumberOfEntries,
                                         MINIDUMP_THREAD_INFO,
                                         ),
                                   )

# Thread extended info stream
MINIDUMP_THREAD_EX = Struct('MINIDUMP_THREAD_EX',
                            ULInt32('ThreadId'),
                            ULInt32('SuspendCount'),
                            ULInt32('PriorityClass'),
                            ULInt32('Priority'),
                            ULInt64('Teb'),
                            MINIDUMP_MEMORY_DESCRIPTOR('Stack'),
                            MINIDUMP_LOCATION_DESCRIPTOR('ThreadContext'),
                            MINIDUMP_MEMORY_DESCRIPTOR('BackingStore'),
                            )

MINIDUMP_THREAD_EX_LIST = Struct('MINIDUMP_THREAD_EX_LIST',
                                 ULInt32('NumberOfThreads'),
                                 Array(lambda ctx: ctx.NumberOfThreads,
                                       MINIDUMP_THREAD_EX,
                                       ),
                                 )

# Function table stream
MINIDUMP_FUNCTION_TABLE_DESCRIPTOR = Struct('MINIDUMP_FUNCTION_TABLE_DESCRIPTOR',
                                            ULInt64('MinimumAddress'),
                                            ULInt64('MaximumAddress'),
                                            ULInt64('BaseAddress'),
                                            ULInt32('EntryCount'),
                                            ULInt32('SizeOfAlignPad'),
                                            HexDumpAdapter(
                                                String(
                                                    'NativeDescriptor',
                                                    lambda ctx: ctx._.SizeOfDescriptor)),
                                            Array(lambda ctx: ctx.EntryCount,
                                                  HexDumpAdapter(
                                                      String(
                                                          'FunctionEntries',
                                                          lambda ctx: ctx._.SizeOfFunctionEntry)),
                                                  ),
                                            Padding(
                                                lambda ctx: ctx.SizeOfAlignPad),
                                            )

MINIDUMP_FUNCTION_TABLE_STREAM = Struct('MINIDUMP_FUNCTION_TABLE_STREAM',
                                        ULInt32('SizeOfHeader'),
                                        ULInt32('SizeOfDescriptor'),
                                        ULInt32('SizeOfNativeDescriptor'),
                                        ULInt32('SizeOfFunctionEntry'),
                                        ULInt32('NumberOfDescriptors'),
                                        ULInt32('SizeOfAlignPad'),
                                        Array(lambda ctx: ctx.NumberOfDescriptors,
                                              MINIDUMP_FUNCTION_TABLE_DESCRIPTOR,
                                              )
                                        )

# Handle operation list
AVRF_MAX_TRACES = 32

HANDLE_TRACE_OPERATIONS = Enum(ULInt32('OperationType'),
                               OperationDbUnused=0,
                               OperationDbOPEN=1,
                               OperationDbCLOSE=2,
                               OperationDbBADREF=3,
                               )

AVRF_BACKTRACE_INFORMATION = Struct("BackTraceInformation",
                                    ULInt32('Depth'),
                                    ULInt32('Index'),
                                    Array(
                                        AVRF_MAX_TRACES,
                                        ULInt64('ReturnAddresses')),
                                    )

AVRF_HANDLE_OPERATION = Struct('AVRF_HANDLE_OPERATION',
                               ULInt64('Handle'),
                               ULInt32('ProcessId'),
                               ULInt32('ThreadId'),
                               HANDLE_TRACE_OPERATIONS,
                               ULInt32('Spare0'),
                               AVRF_BACKTRACE_INFORMATION,
                               )

MINIDUMP_HANDLE_OPERATION_LIST = Struct('MINIDUMP_HANDLE_OPERATION_LIST',
                                        ULInt32('SizeOfHeader'),
                                        ULInt32('SizeOfEntry'),
                                        ULInt32('NumberOfEntries'),
                                        ULInt32('Reserved'),
                                        Array(
                                            lambda ctx: ctx.NumberOfEntries,
                                            AVRF_HANDLE_OPERATION),
                                        )

# Module stream


def GUID(name):
    return Struct(name,
                  ULInt32("Data1"),
                  ULInt16("Data2"),
                  ULInt16("Data3"),
                  String("Data4", 8),
                  )

CV_RSDS_HEADER = Struct("CV_RSDS",
                        Const(Field("Signature", 4), b"RSDS"),
                        GUID("GUID"),
                        ULInt32("Age"),
                        CString("Filename"),
                        )

CV_NB10_HEADER = Struct("CV_NB10",
                        Const(Field("Signature", 4), b"NB10"),
                        ULInt32("Offset"),
                        ULInt32("Timestamp"),
                        ULInt32("Age"),
                        CString("Filename"),
                        )

CV_DATA = Struct("CvData",
                 Peek(Field("_Signature", 4)),
                 IfThenElse("CV_DATA", lambda ctx: ctx._Signature == b"RSDS",
                            Embed(CV_RSDS_HEADER),
                            Embed(CV_NB10_HEADER)
                            ),
                 )

MINIDUMP_MODULE = Struct('MINIDUMP_MODULE',
                         ULInt64('BaseOfImage'),
                         ULInt32('SizeOfImage'),
                         ULInt32('CheckSum'),
                         TimeDateAdapter(ULInt32('TimeDateStamp')),
                         ULInt32('ModuleNameRva'),
                         Pointer(
                             lambda ctx: ctx.ModuleNameRva,
                             MINIDUMP_STRING('ModuleName')),
                         VS_FIXEDFILEINFO('VersionInfo'),
                         MINIDUMP_LOCATION_DESCRIPTOR('CvRecord'),
                         NullPointer(lambda ctx: ctx.CvRecord.RVA, CV_DATA),
                         MINIDUMP_LOCATION_DESCRIPTOR('MiscRecord'),
                         ULInt64('Reserved0'),
                         ULInt64('Reserved1'),
                         )

MINIDUMP_MODULE_LIST = Struct('MINIDUMP_MODULE_LIST',
                              ULInt32('NumberOfModules'),
                              Array(lambda ctx: ctx.NumberOfModules,
                                    MINIDUMP_MODULE,
                                    ),
                              )

# Memory info stream
MINIDUMP_MEMORY_LIST = Struct('MINIDUMP_MEMORY_LIST',
                              ULInt32('NumberOfMemoryRanges'),
                              Array(
                                  lambda ctx: ctx.NumberOfMemoryRanges,
                                  MINIDUMP_MEMORY_DESCRIPTOR('MemoryRanges')),
                              )

# Memory list (64-bit)
MINIDUMP_MEMORY_DESCRIPTOR64 = Struct('MINIDUMP_MEMORY_DESCRIPTOR64',
                                      ULInt64('StartOfMemoryRange'),
                                      ULInt64('DataSize'),
                                      )

MINIDUMP_MEMORY64_LIST = Struct('MINIDUMP_MEMORY64_LIST',
                                ULInt64('NumberOfMemoryRanges'),
                                ULInt64('BaseRva'),
                                Array(
                                    lambda ctx: ctx.NumberOfMemoryRanges,
                                    MINIDUMP_MEMORY_DESCRIPTOR64),
                                )

# Memory info list
MEM_STATE = FlagsEnum(ULInt32("State"),
                      MEM_COMMIT=0x1000,
                      MEM_FREE=0x10000,
                      MEM_RESERVE=0x2000,
                      )

MEM_TYPE = FlagsEnum(ULInt32("Type"),
                     MEM_IMAGE=0x1000000,
                     MEM_MAPPED=0x40000,
                     MEM_PRIVATE=0x20000,
                     )


def MEM_PROTECT(name):
    return FlagsEnum(ULInt32(name),
                     PAGE_NOACCESS=0x0001,
                     PAGE_READONLY=0x0002,
                     PAGE_READWRITE=0x0004,
                     PAGE_WRITECOPY=0x0008,
                     PAGE_EXECUTE=0x0010,
                     PAGE_EXECUTE_READ=0x0020,
                     PAGE_EXECUTE_READWRITE=0x0040,
                     PAGE_EXECUTE_WRITECOPY=0x0080,
                     PAGE_GUARD=0x0100,
                     PAGE_NOCACHE=0x0200,
                     PAGE_WRITECOMBINE=0x0400,
                     )

def MEM_PROTECT_to_string(flags):
    for p in PAGE_ACCESS.keys():
        if flags[p]:
            return PAGE_ACCESS[p]
    return PAGE_ACCESS['PAGE_NOACCESS']

PAGE_ACCESS = {
    'PAGE_NOACCESS': "---",
    'PAGE_READONLY': "r--",
    'PAGE_READWRITE': "rw-",
    'PAGE_WRITECOPY': "rc-",
    'PAGE_EXECUTE': "--x",
    'PAGE_EXECUTE_READ': "r-x",
    'PAGE_EXECUTE_READWRITE': "rwx",
    'PAGE_EXECUTE_WRITECOPY': "rcx",
    #'PAGE_GUARD'=0x0100,
    #'PAGE_NOCACHE'=0x0200,
    #'PAGE_WRITECOMBINE'=0x0400,
}


MINIDUMP_MEMORY_INFO = Struct('MINIDUMP_MEMORY_INFO',
                              ULInt64('BaseAddress'),
                              ULInt64('AllocationBase'),
                              MEM_PROTECT('AllocationProtect'),
                              ULInt32('__alignment1'),
                              ULInt64('RegionSize'),
                              MEM_STATE,
                              MEM_PROTECT('Protect'),
                              MEM_TYPE,
                              ULInt32('__alignment2'),
                              )

MINIDUMP_MEMORY_INFO_LIST = Struct('MINIDUMP_MEMORY_INFO_LIST',
                                   ULInt32('SizeOfHeader'),
                                   ULInt32('SizeOfEntry'),
                                   ULInt64('NumberOfEntries'),
                                   Array(
                                       lambda ctx: ctx.NumberOfEntries,
                                       MINIDUMP_MEMORY_INFO),
                                   )

# Handle info stream
HANDLE_OBJECT_INFORMATION_TYPE = Enum(ULInt32("InfoType"),
                                      MiniHandleObjectInformationNone=0,
                                      MiniThreadInformation1=1,
                                      MiniMutantInformation1=2,
                                      MiniMutantInformation2=3,
                                      MiniProcessInformation1=4,
                                      MiniProcessInformation2=5,
                                      )

MINIDUMP_HANDLE_OBJECT_INFORMATION = Struct('MINIDUMP_HANDLE_OBJECT_INFORMATION',
                                            ULInt32('NextInfoRva'),
                                            NullPointer(lambda ctx: ctx.NextInfoRva,
                                                        LazyBound(
                                                            "NextInfo",
                                                            lambda: MINIDUMP_HANDLE_OBJECT_INFORMATION)
                                                        ),
                                            HANDLE_OBJECT_INFORMATION_TYPE,
                                            ULInt32('SizeOfInfo'),
                                            HexDumpAdapter(
                                                String(
                                                    "InfoBlock",
                                                    lambda ctx: ctx.SizeOfInfo)),
                                            )

MINIDUMP_HANDLE_DESCRIPTOR = Struct('MINIDUMP_HANDLE_DESCRIPTOR',
                                    ULInt64('Handle'),
                                    ULInt32('TypeNameRva'),
                                    NullPointer(
                                        lambda ctx: ctx.TypeNameRva,
                                        MINIDUMP_STRING('TypeName')),
                                    ULInt32('ObjectNameRva'),
                                    NullPointer(
                                        lambda ctx: ctx.ObjectNameRva,
                                        MINIDUMP_STRING('ObjectName')),
                                    ULInt32('Attributes'),
                                    ULInt32('GrantedAccess'),
                                    ULInt32('HandleCount'),
                                    ULInt32('PointerCount'),
                                    )

MINIDUMP_HANDLE_DESCRIPTOR_2 = Struct('MINIDUMP_HANDLE_DESCRIPTOR_2',
                                      ULInt64('Handle'),
                                      ULInt32('TypeNameRva'),
                                      NullPointer(
                                          lambda ctx: ctx.TypeNameRva,
                                          MINIDUMP_STRING('TypeName')),
                                      ULInt32('ObjectNameRva'),
                                      NullPointer(
                                          lambda ctx: ctx.ObjectNameRva,
                                          MINIDUMP_STRING('ObjectName')),
                                      ULInt32('Attributes'),
                                      ULInt32('GrantedAccess'),
                                      ULInt32('HandleCount'),
                                      ULInt32('PointerCount'),
                                      ULInt32('ObjectInfoRva'),
                                      NullPointer(
                                          lambda ctx: ctx.ObjectInfoRva,
                                          MINIDUMP_HANDLE_OBJECT_INFORMATION),
                                      ULInt32('Reserved0'),
                                      )

MINIDUMP_HANDLE_DATA_STREAM = Struct('MINIDUMP_HANDLE_DATA_STREAM',
                                     ULInt32('SizeOfHeader'),
                                     ULInt32('SizeOfDescriptor'),
                                     ULInt32('NumberOfDescriptors'),
                                     ULInt32('Reserved'),
                                     IfThenElse("HandleDataList", lambda ctx: ctx.SizeOfDescriptor == 0x28,
                                                Array(
                                                    lambda ctx: ctx.NumberOfDescriptors,
                                                    MINIDUMP_HANDLE_DESCRIPTOR_2),
                                                Array(
                                                    lambda ctx: ctx.NumberOfDescriptors,
                                                    MINIDUMP_HANDLE_DESCRIPTOR),
                                                )
                                     )

# Window handle stream, 0x10000


def UNICODE_STRING(name):
    return Struct(name,
                  ULInt32('Length'),
                  ULInt32('MaximumLength'),
                  ULInt32('Buffer'),
                  )


def RECT(name):
    return Struct(name,
                  SLInt32('left'),
                  SLInt32('top'),
                  SLInt32('right'),
                  SLInt32('bottom'),
                  )

MINIDUMP_WINDOW_HANDLE = Struct("WindowHandles",
                                Const(ULInt64('Signature'), 0xcafe),
                                ULInt32('SizeOfHandle'),
                                Enum(ULInt32('WindowCharset'),
                                     ANSI=0,
                                     UNICODE=1,
                                     ),
                                NullStringAdapter(
                                    String(
                                        'ClassName',
                                        0x80,
                                        encoding='utf-16-le')),
                                NullStringAdapter(
                                    String(
                                        'WindowName',
                                        0x80,
                                        encoding='utf-16-le')),
                                ULInt32('PID'),
                                ULInt32('TID'),
                                NullStringAdapter(
                                    String(
                                        'ModuleFileName',
                                        0x200,
                                        encoding='utf-16-le')),
                                ULInt32('Unknown2'),
                                ULInt32('Unknown3'),
                                ULInt32('hwnd'),
                                ULInt32('Unknown4'),
                                ULInt32('pProcessUnkBlock'),
                                ULInt32('pDesktop'),
                                ULInt32('pwnd'),
                                ULInt32('state'),
                                ULInt32('state2'),
                                ULInt32('ExStyle'),
                                ULInt32('style'),
                                ULInt32('hModule'),
                                ULInt16('fnid'),
                                ULInt16('unk_short'),
                                ULInt32('spwndNext'),
                                ULInt32('spwndPrevious'),
                                ULInt32('spwndParent'),
                                ULInt32('spwndChild'),
                                ULInt32('spwndOwner'),
                                RECT('rcWindow'),
                                RECT('rcClient'),
                                ULInt32('wndproc'),
                                ULInt32('pcls'),
                                ULInt32('unk_hrgnUpdate'),
                                ULInt32('ppropList'),
                                ULInt32('pSBInfo'),
                                ULInt32('spmenuSys'),
                                ULInt32('spmenu'),
                                ULInt32('hrgnClip'),
                                UNICODE_STRING('WindowNameKernelMode'),
                                ULInt32('Unknown8'),
                                ULInt32('spwndLastActive'),
                                ULInt32('hImc'),
                                ULInt32('dwUserData'),
                                ULInt32('pActCtx'),
                                )

MINIDUMP_WINDOW_HANDLE_STREAM = Tunnel(
    Field("Data", lambda ctx: ctx.Location.DataSize),
    GreedyRange(MINIDUMP_WINDOW_HANDLE),
)

# Unloaded module list stream
MINIDUMP_UNLOADED_MODULE = Struct('MINIDUMP_UNLOADED_MODULE',
                                  ULInt64('BaseOfImage'),
                                  ULInt32('SizeOfImage'),
                                  ULInt32('CheckSum'),
                                  TimeDateAdapter(ULInt32('TimeDateStamp')),
                                  ULInt32('ModuleNameRva'),
                                  Pointer(
                                      lambda ctx: ctx.ModuleNameRva,
                                      MINIDUMP_STRING('ModuleName')),
                                  )

MINIDUMP_UNLOADED_MODULE_LIST = Struct('MINIDUMP_UNLOADED_MODULE_LIST',
                                       ULInt32('SizeOfHeader'),
                                       ULInt32('SizeOfEntry'),
                                       ULInt32('NumberOfEntries'),
                                       Array(
                                           lambda ctx: ctx.NumberOfEntries,
                                           MINIDUMP_UNLOADED_MODULE),
                                       )

# Exception record stream
EXCEPTION_CODE = Enum(ULInt32('ExceptionCode'),
                      DBG_CONTROL_C=0x40010005,
                      EXCEPTION_GUARD_PAGE_VIOLATION=0x80000001,
                      EXCEPTION_DATATYPE_MISALIGNMENT=0x80000002,
                      EXCEPTION_BREAKPOINT=0x80000003,
                      EXCEPTION_SINGLE_STEP=0x80000004,
                      EXCEPTION_ACCESS_VIOLATION=0xc0000005,
                      EXCEPTION_IN_PAGE_ERROR=0xc0000006,
                      EXCEPTION_INVALID_HANDLE=0xc0000008,
                      EXCEPTION_ILLEGAL_INSTRUCTION=0xc000001d,
                      EXCEPTION_NONCONTINUABLE_EXCEPTION=0xc0000025,
                      EXCEPTION_INVALID_DISPOSITION=0xc0000026,
                      EXCEPTION_ARRAY_BOUNDS_EXCEEDED=0xc000008c,
                      EXCEPTION_FLOAT_DENORMAL_OPERAND=0xc000008d,
                      EXCEPTION_FLOAT_DIVIDE_BY_ZERO=0xc000008e,
                      EXCEPTION_FLOAT_INEXACT_RESULT=0xc000008f,
                      EXCEPTION_FLOAT_INVALID_OPERATION=0xc0000090,
                      EXCEPTION_FLOAT_OVERFLOW=0xc0000091,
                      EXCEPTION_FLOAT_STACK_CHECK=0xc0000092,
                      EXCEPTION_FLOAT_UNDERFLOW=0xc0000093,
                      EXCEPTION_INTEGER_DIVIDE_BY_ZERO=0xc0000094,
                      EXCEPTION_INTEGER_OVERFLOW=0xc0000095,
                      EXCEPTION_PRIVILEGED_INSTRUCTION=0xc0000096,
                      EXCEPTION_STACK_OVERFLOW=0xc00000fd,
                      EXCEPTION_POSSIBLE_DEADLOCK=0xc0000194,
                      _default_=Pass,
                      )

EXCEPTION_FLAGS = Enum(ULInt32('ExceptionFlags'),
                       EXCEPTION_CONTINUABLE=0,
                       EXCEPTION_NONCONTINUABLE=1,
                       )

EXCEPTION_MAXIMUM_PARAMETERS = 15

MINIDUMP_EXCEPTION = Struct('MINIDUMP_EXCEPTION',
                            EXCEPTION_CODE,
                            EXCEPTION_FLAGS,
                            ULInt64('ExceptionRecord'),
                            NullPointer(lambda ctx: ctx.ExceptionRecord,
                                        LazyBound(
                                            "RelatedExceptionRecord",
                                            lambda: MINIDUMP_EXCEPTION)
                                        ),
                            ULInt64('ExceptionAddress'),
                            ULInt32('NumberParameters'),
                            ULInt32('__unusedAlignment'),
                            Array(
                                lambda ctx: EXCEPTION_MAXIMUM_PARAMETERS,
                                ULInt64('ExceptionInformation')),
                            )

MINIDUMP_EXCEPTION_STREAM = Struct('MINIDUMP_EXCEPTION_STREAM',
                                   ULInt32('ThreadId'),
                                   ULInt32('__alignment'),
                                   MINIDUMP_EXCEPTION,
                                   MINIDUMP_LOCATION_DESCRIPTOR(
                                       'ThreadContext'),
                                   )

# System info stream
SYSTEM_INFO_SUITEMASK = FlagsEnum(ULInt16("SuiteMask"),
                                  VER_SUITE_SMALLBUSINESS=0x0001,
                                  VER_SUITE_ENTERPRISE=0x0002,
                                  VER_SUITE_BACKOFFICE=0x0004,
                                  VER_SUITE_TERMINAL=0x0010,
                                  VER_SUITE_SMALLBUSINESS_RESTRICTED=0x0020,
                                  VER_SUITE_EMBEDDEDNT=0x0040,
                                  VER_SUITE_DATACENTER=0x0080,
                                  VER_SUITE_SINGLEUSERTS=0x0100,
                                  VER_SUITE_PERSONAL=0x0200,
                                  VER_SUITE_BLADE=0x0400,
                                  VER_SUITE_STORAGE_SERVER=0x2000,
                                  VER_SUITE_COMPUTE_SERVER=0x4000,
                                  )

SYSTEM_INFO_PROCESSOR_ARCH = Enum(ULInt16("ProcessorArchitecture"),
                                  PROCESSOR_ARCHITECTURE_X86=0,
                                  PROCESSOR_ARCHITECTURE_MIPS=1,
                                  PROCESSOR_ARCHITECTURE_ALPHA=2,
                                  PROCESSOR_ARCHITECTURE_PPC=3,
                                  PROCESSOR_ARCHITECTURE_SHX=4,
                                  PROCESSOR_ARCHITECTURE_ARM=5,
                                  PROCESSOR_ARCHITECTURE_IA64=6,
                                  PROCESSOR_ARCHITECTURE_ALPHA64=7,
                                  PROCESSOR_ARCHITECTURE_MSIL=8,
                                  PROCESSOR_ARCHITECTURE_AMD64=9,
                                  PROCESSOR_ARCHITECTURE_X86_WIN64=10,
                                  PROCESSOR_ARCHITECTURE_UNKNOWN=0xffff,
                                  )

SYSTEM_INFO_PLATFORMID = Enum(ULInt32("PlatformID"),
                              VER_PLATFORM_WIN32s=0,
                              VER_PLATFORM_WIN32_WINDOWS=1,
                              VER_PLATFORM_WIN32_NT=2,
                              VER_PLATFORM_WIN32_CE=3,
                              _default_=Pass,
                              )
SYSTEM_INFO_PRODUCT_TYPE = Enum(ULInt8("ProductType"),
                                VER_NT_WORKSTATION=1,
                                VER_NT_DOMAIN_CONTROLLER=2,
                                VER_NT_SERVER=3,
                                _default_=Pass,
                                )

MINIDUMP_SYSTEM_INFO = Struct('MINIDUMP_SYSTEM_INFO',
                              SYSTEM_INFO_PROCESSOR_ARCH,
                              ULInt16('ProcessorLevel'),
                              ULInt16('ProcessorRevision'),
                              ULInt8('NumberOfProcessors'),
                              SYSTEM_INFO_PRODUCT_TYPE,
                              ULInt32('MajorVersion'),
                              ULInt32('MinorVersion'),
                              ULInt32('BuildNumber'),
                              SYSTEM_INFO_PLATFORMID,
                              ULInt32('CSDVersionRva'),
                              Pointer(
                                  lambda ctx: ctx.CSDVersionRva,
                                  MINIDUMP_STRING('CSDVersion')),
                              SYSTEM_INFO_SUITEMASK,
                              ULInt16('Reserved2'),
                              Union('Cpu',
                                    Struct('X86CpuInfo',
                                           Array(3, ULInt32('VendorId')),
                                           ULInt32('VersionInformation'),
                                           ULInt32('FeatureInformation'),
                                           ULInt32('AMDExtendedCpuFeatures'),
                                           ),
                                    Struct('OtherCpuInfo',
                                           Array(
                                               2,
                                               ULInt64('ProcessorFeatures')),
                                           ),
                                    ),
                              )

# Misc info stream
MISC_INFO_FLAGS = FlagsEnum(ULInt32("Flags1"),
                            MINIDUMP_MISC1_PROCESS_ID=0x00000001,
                            MINIDUMP_MISC1_PROCESS_TIMES=0x00000002,
                            MINIDUMP_MISC1_PROCESSOR_POWER_INFO=0x00000004,
                            )

MINIDUMP_MISC_INFO = Struct('MINIDUMP_MISC_INFO',
                            ULInt32('SizeOfInfo'),
                            MISC_INFO_FLAGS,
                            If(lambda ctx: ctx.Flags1.MINIDUMP_MISC1_PROCESS_ID,
                                ULInt32('ProcessId'),
                               ),
                            If(lambda ctx: ctx.Flags1.MINIDUMP_MISC1_PROCESS_TIMES,
                                Embed(Struct("ProcessTimes",
                                             TimeDateAdapter(
                                                 ULInt32('ProcessCreateTime')),
                                             TimeDeltaAdapter(
                                                 ULInt32('ProcessUserTime')),
                                             TimeDeltaAdapter(
                                                 ULInt32('ProcessKernelTime')),
                                             )),
                               ),
                            If(lambda ctx: ctx.Flags1.MINIDUMP_MISC1_PROCESSOR_POWER_INFO,
                                Embed(Struct("ProcessorPowerInfo",
                                             ULInt32('ProcessorMaxMhz'),
                                             ULInt32('ProcessorCurrentMhz'),
                                             ULInt32('ProcessorMhzLimit'),
                                             ULInt32('ProcessorMaxIdleState'),
                                             ULInt32(
                                                 'ProcessorCurrentIdleState'),
                                             )),
                               ),
                            )

# Directory entries


def DirectoryEntry(kind):
    return Pointer(lambda ctx: ctx.Location.RVA, kind)

MINIDUMP_DIRECTORY = Struct('MINIDUMP_DIRECTORY',
                            MINIDUMP_STREAM_TYPE,
                            MINIDUMP_LOCATION_DESCRIPTOR('Location'),
                            Switch("DirectoryData", lambda ctx: ctx.StreamType, {
                                'ThreadListStream': DirectoryEntry(MINIDUMP_THREAD_LIST),
                                'ThreadInfoListStream': DirectoryEntry(MINIDUMP_THREAD_INFO_LIST),
                                'ThreadExListStream': DirectoryEntry(MINIDUMP_THREAD_EX_LIST),
                                'ModuleListStream': DirectoryEntry(MINIDUMP_MODULE_LIST),
                                'MemoryListStream': DirectoryEntry(MINIDUMP_MEMORY_LIST),
                                'MemoryInfoListStream': DirectoryEntry(MINIDUMP_MEMORY_INFO_LIST),
                                'Memory64ListStream': DirectoryEntry(MINIDUMP_MEMORY64_LIST),
                                'ExceptionStream': DirectoryEntry(MINIDUMP_EXCEPTION_STREAM),
                                'UnloadedModuleListStream': DirectoryEntry(MINIDUMP_UNLOADED_MODULE_LIST),
                                'HandleDataStream': DirectoryEntry(MINIDUMP_HANDLE_DATA_STREAM),
                                'HandleOperationListStream': DirectoryEntry(MINIDUMP_HANDLE_OPERATION_LIST),
                                'WindowHandleInfoStream': DirectoryEntry(MINIDUMP_WINDOW_HANDLE_STREAM),
                                'SystemInfoStream': DirectoryEntry(MINIDUMP_SYSTEM_INFO),
                                'MiscInfoStream': DirectoryEntry(MINIDUMP_MISC_INFO),
                                'CommentStreamA': DirectoryEntry(
                                    String(
                                        "MINIDUMP_COMMENT_A",
                                        lambda ctx: ctx.Location.DataSize)
                                ),
                                'CommentStreamW': DirectoryEntry(
                                    String(
                                        "MINIDUMP_COMMENT_W",
                                        lambda ctx: ctx.Location.DataSize,
                                        encoding='utf-16-le')
                                ),
                            },
                                default=Pointer(lambda ctx: ctx.Location.RVA,
                                                HexDumpAdapter(
                                                    Field(
                                                        "Data",
                                                        lambda ctx: ctx.Location.DataSize)),
                                                ),
                            ),
                            )

MINIDUMP_HEADER = Debugger(Struct('MINIDUMP_HEADER',
                                  Const(Field("Signature", 4), b"MDMP"),
                                  ULInt16('Version'),
                                  ULInt16('ImplementationVersion'),
                                  ULInt32('NumberOfStreams'),
                                  ULInt32('StreamDirectoryRva'),
                                  Pointer(lambda ctx: ctx.StreamDirectoryRva,
                                          Array(lambda ctx: ctx.NumberOfStreams,
                                                MINIDUMP_DIRECTORY,
                                                ),
                                          ),
                                  ULInt32('CheckSum'),
                                  Union('ts_reserved',
                                        ULInt32('Reserved'),
                                        TimeDateAdapter(
                                            ULInt32('TimeDateStamp')),
                                        ),
                                  MINIDUMP_TYPES,
                                  ))

# from haystack.mappings import FileMapping
from haystack import target
from haystack.abc import interfaces
from haystack.mappings import base

import os
import mmap
import logging


log = logging.getLogger("minidump")


class MDMP_Mapper(interfaces.IMemoryLoader):
    """Container:
            StreamType = 'Memory64ListStream'
            Location = Container:
                DataSize = 3856
                RVA = 11883
            DirectoryData = Container:
                NumberOfMemoryRanges = 240
                BaseRva = 15739
                MINIDUMP_MEMORY_DESCRIPTOR64 = [
                    Container:
                        StartOfMemoryRange = 65536
                        DataSize = 4096
    """

    def __init__(self, filename, cpu=None, os_name=None):
        construct_data = MINIDUMP_HEADER.parse_stream(open(filename, 'rb'))
        #
        self.filename = os.path.abspath(filename)
        self.dumpname = os.path.basename(filename)
        self.cpu = cpu
        self.os_name = os_name
        self._init_mappings(construct_data)

    def _init_mappings(self, construct_data):
        content_file = open(self.filename, 'rb')
        fsize = os.path.getsize(self.filename)
        # FIXME, can't close it because we need fileno ? mmap usage
        mmap_content = mmap.mmap(
                    content_file.fileno(),
                    fsize,
                    access=mmap.ACCESS_READ)
        log.debug("fsize: %d", fsize)
        maps = []
        maps_info = {}
        #
        # get the named modules
        named_modules = {}
        for directory in construct_data.MINIDUMP_DIRECTORY:
            if directory.StreamType == 'ModuleListStream':
                for _range in directory.DirectoryData.MINIDUMP_MODULE:
                    start = _range.BaseOfImage
                    size = _range.SizeOfImage
                    for page_start in range(start, start+size, 0x1000):
                        named_modules[page_start] = (size, _range.ModuleName)
        # BUG ?
        # the last mapping is sometimes incomplete, and seems to be the PE file.
        for directory in construct_data.MINIDUMP_DIRECTORY:
            if directory.StreamType == 'Memory64ListStream':
                #print directory
                #print directory.DirectoryData.NumberOfMemoryRanges, "mappings"
                offset = directory.DirectoryData.BaseRva
                map_offset = offset
                prev_size = 0
                for _range in directory.DirectoryData.MINIDUMP_MEMORY_DESCRIPTOR64:
                    map_offset += prev_size
                    start = _range.StartOfMemoryRange
                    size = _range.DataSize
                    if map_offset+size > fsize:
                        log.error('BAD FILE: reducing mapping 0x%x-0x%x size 0x%x -> 0x%x bytes', start, start+size, size, fsize - map_offset)
                        size = fsize - map_offset
                    end = start + size
                    log.debug("Memory64ListStream 0x%x-0x%x size:0x%x offset_in_file:0x%x", start, start+size, size, map_offset)
                    ## BUG FIXME, offset reading ???
                    name = 'None'
                    if start in named_modules:
                        name = named_modules[start][1]
                    maps.append(file.MMapProcessMapping(mmap_content, start, end, offset=map_offset, pathname=name))
                    prev_size = size
            elif directory.StreamType == 'MemoryInfoListStream':
                ## Collect all metadata information
                nb_entries = directory.DirectoryData.NumberOfEntries
                for _range in directory.DirectoryData.MINIDUMP_MEMORY_INFO:
                    start = _range.BaseAddress
                    size = _range.RegionSize
                    log.debug("MemoryInfoListStream 0x%x-0x%x size:0x%x ", start, start+size, size)
                    maps_info[start] = (_range, start, size)
        ## FAST FAIL
        if len(maps) == 0:
            raise TypeError('This Minidump does not contain Memory64ListStream memory dump. ' +
                            'Please use full memory dump options in the memory acquisition tool.')
        missing_info = [x.start for x in maps if x.start not in maps_info]
        if len(missing_info) > 0:
            log.debug('Missing metadata MemoryInfoListStream. %d mappings missing', len(missing_info))
        else:
            # enrich data with MemoryInfoListStream
            for m in maps:
                if m.start not in maps_info:
                    continue
                # fix permissions
                info, start, size = maps_info[m.start]
                del maps_info[m.start]
                if size != len(m):
                    log.warning("incorrect size metadata on 0x%x", m.start)
                m.permissions = MEM_PROTECT_to_string(info.Protect)
        # Ignore the remaining mappiongs
        for start, (info, start, size) in maps_info.items():
            permissions = MEM_PROTECT_to_string(info.Protect)
            # maps.append(base.AMemoryMapping(start, start+size, permissions, 0, 0, 0, 0, "*unknown*"))
            log.debug("ignore uncaptured MemoryMapping: %s", base.AMemoryMapping(start, start+size, permissions, 0, 0, 0, 0, "*unknown*"))
        # target
        cpu = os_name = None
        if self.os_name is None or self.cpu is None:
            # then resolve it
            for directory in construct_data.MINIDUMP_DIRECTORY:
                if directory.StreamType == 'SystemInfoStream':
                    data = directory.DirectoryData
                    if data.MajorVersion == 5:
                        os_name = 'winxp'
                    else:
                        os_name = 'win7'
                    # the heapfinder would have to make a difference.
                    if 'X86' in data.ProcessorArchitecture:
                        cpu = 32
                    else:
                        cpu = 64
                    break
        if self.os_name is None:
            self.os_name = os_name
        if self.os_name not in ['winxp', 'win7']:
            raise NotImplementedError('Unsupported os : %s' % self.os_name)
        if self.cpu is None:
            self.cpu = cpu
        # now set the target
        if self.cpu == 32:
            self._target = target.TargetPlatform.make_target_win_32(self.os_name)
        elif self.cpu == 64:
            self._target = target.TargetPlatform.make_target_win_64(self.os_name)

        #
        self.mappings = maps
        self.maps_info = maps_info
        log.debug("nb maps: %d", len(self.mappings))
        log.debug("target: %s", self._target)
        # Use a folder name for its cache later on
        h_name = self.filename + ".d"
        memory_handler = base.MemoryHandler(self.mappings, self._target, h_name)
        self._memory_handler = memory_handler
        return

    def make_memory_handler(self):
        return self._memory_handler


if __name__ == "__main__":
    import sys
    x = MINIDUMP_HEADER.parse_stream(open(sys.argv[1], 'rb'))
    print(x)
    mapper = MDMP_Mapper(sys.argv[1], None, None)
    for m in mapper.mappings:
        print(m)
    import code
    code.interact(local=locals())
