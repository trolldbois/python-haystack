#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import dump_loader
from haystack import utils
from haystack.outputters import text
from haystack.outputters import python

from test.haystack import SrcTests


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

class TestToPyObject(SrcTests):
    """Basic types"""
    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
    
    def tearDown(self):
        from haystack import model
        model.reset()
        self.mappings = None
        pass

    def test_complex(self):
        from test.src import ctypes5_gen32
        model.registerModule(ctypes5_gen32)
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.mappings.getMmapForAddr(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)

        import ctypes
        self.assertEquals(int(self.sizes['struct_d']), ctypes.sizeof(d))
        
        obj = d.toPyObject()
        #print obj.toString()
        import code
        #print obj.f.toString()
        #code.interact(local=locals())
        ## void pointer
        self.assertEquals(None, obj.a)
        #
        self.assertEquals(int(self.values['struct_d.b.e']), obj.b.e)
        self.assertEquals(int(self.values['struct_d.b2.e']), obj.b2.e)
        for i in range(9):
            self.assertEquals(int(self.values['struct_d.c[%d].a'%(i)]), obj.c[i].a)
            self.assertEquals(int(self.values['struct_d.f[%d]'%(i)]), obj.f[i])
        self.assertEquals(int(self.values['struct_d.e']), obj.e)
        # FIXME: how do you exprime a CString with a POINTER(c_char)
        #self.assertEquals(str(self.values['struct_d.h']), obj.h)
        self.assertEquals(str(self.values['struct_d.i']), obj.i)

        
        return 

    @unittest.expectedFailure
    def test_CString(self):
        from test.src import ctypes5_gen32
        model.registerModule(ctypes5_gen32)
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.mappings.getMmapForAddr(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(self.mappings, 10 )

        obj = d.toPyObject()
        # FIXME: how do you exprime a CString with a POINTER(c_char)
        self.assertEquals(str(self.values['struct_d.h']), obj.h)

        return 





if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)

