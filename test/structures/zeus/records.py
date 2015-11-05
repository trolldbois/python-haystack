import ctypes


class array_of_pointers(ctypes.Structure):
    _fields_ = [('array', ctypes.CString*82)]


class array_of_wcharp(ctypes.Structure):
    _fields_ = [('array', ctypes.CWString*82)]
