#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

# init ctypes with a controlled type size
from haystack import model
from haystack import types

import operator
import os
import logging
import struct
import unittest

class TestWalkers(unittest.TestCase):
    """Tests walkers after ctypes changes."""

    def setUp(self):
        model.reset()

    def tearDown(self):
        model.reset()
    
    
    def test_walker_after_arch_change(self):
        x32 = types.reload_ctypes(4,4,8)
        x64 = types.reload_ctypes(8,8,16)

        from haystack.structures.libc import libcheapwalker
        from haystack.structures.win32 import winheapwalker
        from haystack.structures.win32 import win7heapwalker

        if False:
            # set the arch
            ctypes = types.set_ctypes(x32)
            libc_x32 = libcheapwalker.LibcHeapFinder()
            winxp_x32 = winheapwalker.WinHeapFinder()
            win7_x32 = win7heapwalker.Win7HeapFinder()
            
            from haystack.structures.win32 import win7heap
            t = win7heap.HEAP_ENTRY
            
            for fi,tp in t._fields_:
                f = getattr(t,fi)
                print fi,' : ', hex(f.offset), hex(f.size)
            
            self.assertEquals(ctypes.sizeof(libc_x32.heap_type), 8)
            self.assertEquals(ctypes.sizeof(winxp_x32.heap_type), 1430)
            self.assertEquals(ctypes.sizeof(win7_x32.heap_type), 312) #0x138
        
        # set the arch
        ctypes = types.set_ctypes(x64)
        libc_x64 = libcheapwalker.LibcHeapFinder()
        winxp_x64 = winheapwalker.WinHeapFinder()
        win7_x64 = win7heapwalker.Win7HeapFinder()
        
        #import code
        #code.interact(local=locals())
        self.assertEquals(ctypes.sizeof(libc_x64.heap_type), 16)
        self.assertEquals(ctypes.sizeof(winxp_x64.heap_type), 2754) # who knows...
        self.assertEquals(ctypes.sizeof(win7_x64.heap_type), 520) 
        
        # try x32 while there
        self.assertEquals(ctypes.sizeof(libc_x32.heap_type), 8)
        self.assertEquals(ctypes.sizeof(winxp_x32.heap_type), 1430)
        self.assertEquals(ctypes.sizeof(win7_x32.heap_type), 312) 
        
            
    
if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main(verbosity=2)


