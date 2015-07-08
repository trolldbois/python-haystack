# -*- coding: utf-8 -*-

import ctypes
BLOCK_SIZE = 16


class Struct2(ctypes.Structure):
    _fields_ = [
        ('field1', ctypes.c_ulong),
        ('field2', ctypes.c_ubyte * BLOCK_SIZE)
    ]

    def getCount(self):
        rd_key = int(self.field1)

    def fromPyObj(self, pyobj):
        self.field1 = pyobj.field1
        # FIXME self._memory_handler.get_ctypes_utils().bytes2array
        self.field2 = bytes2array(pyobj.field2, ctypes.c_ubyte)
        return self
