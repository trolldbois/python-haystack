#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack import utils


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class SrcTests(unittest.TestCase):
    def _load_offsets_values(self, dumpname):
        """read <dumpname>.stdout to get offsets given by the binary."""
        offsets = dict()
        values = dict()
        sizes = dict()
        for line in open('%s.stdout'%(dumpname[:-len('.dump')]),'rb').readlines():
            if line.startswith('s: '):
                # start
                fields = line[3:].split(' ')
                name = fields[0].strip()
            elif line.startswith('o: '):
                # offset
                fields = line[3:].split(' ')
                k,v = fields[0],int(fields[1].strip(),16)
                if k not in offsets:
                    offsets[k]=[]
                offsets[k].append(v)
            elif line.startswith('v: '):
                # value of members
                fields = line[3:].split(' ')
                k,v = fields[0],fields[1].strip()
                n = '%s.%s'%(name,k)
                values[n] = v
            elif line.startswith('t: '): 
                # sizeof
                fields = line[3:].split(' ')
                k,v = fields[0],fields[1].strip()
                sizes[name] = v
        self.values = values
        self.offsets = offsets
        self.sizes = sizes
        return 


class TestLoadMembers(SrcTests):
    """Basic types"""
    def setUp(self):
        self.mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
    
    def tearDown(self):
        from haystack import model
        model.reset()
        self.mappings = None
        pass
    
    def test_basic_types(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['struct_a'][0]
        m = self.mappings.getMmapForAddr(offset)
        a = m.readStruct(offset, ctypes5_gen32.struct_a)
        ret = a.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        import ctypes
        self.assertEquals(int(self.sizes['struct_a']), ctypes.sizeof(a))

        self.assertEquals(int(self.values['struct_a.a']), a.a)
        self.assertEquals(int(self.values['struct_a.b']), a.b)
        self.assertEquals(int(self.values['struct_a.c']), a.c)
        self.assertEquals(int(self.values['struct_a.d']), a.d)
        self.assertEquals(int(self.values['struct_a.e']), a.e)
        self.assertEquals(float(self.values['struct_a.f']), a.f)
        self.assertEquals(float(self.values['struct_a.g']), a.g)
        self.assertEquals(float(self.values['struct_a.h']), a.h)


        offset = self.offsets['union_au'][0]
        m = self.mappings.getMmapForAddr(offset)
        au = m.readStruct(offset, ctypes5_gen32.union_au)
        ret = au.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        self.assertEquals(int(self.sizes['union_au']), ctypes.sizeof(au))
        self.assertEquals(int(self.values['union_au.d']), au.d)
        self.assertEquals(float(self.values['union_au.g']), au.g)
        self.assertEquals(float(self.values['union_au.h']), au.h)
        
        return 

    def test_basic_signed_types(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['union_b'][0]
        m = self.mappings.getMmapForAddr(offset)
        b = m.readStruct(offset, ctypes5_gen32.union_b)
        ret = b.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        import ctypes
        self.assertEquals(int(self.sizes['union_b']), ctypes.sizeof(b))
        self.assertEquals(int(self.values['union_b.a']), b.a)
        self.assertEquals(int(self.values['union_b.b']), b.b)
        self.assertEquals(int(self.values['union_b.c']), b.c)
        self.assertEquals(int(self.values['union_b.d']), b.d)
        self.assertEquals(int(self.values['union_b.e']), b.e)
        
        return 

    def test_bitfield(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['struct_c'][0]
        m = self.mappings.getMmapForAddr(offset)
        c = m.readStruct(offset, ctypes5_gen32.struct_c)
        ret = c.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        print c

        import ctypes
        self.assertEquals(int(self.sizes['struct_c']), ctypes.sizeof(c))

        #import code
        #code.interact(local=locals())
        self.assertEquals(int(self.values['struct_c.a']), c.a)
        self.assertEquals(int(self.values['struct_c.b']), c.b)
        self.assertEquals(int(self.values['struct_c.c']), c.c)
        self.assertEquals(int(self.values['struct_c.d']), c.d)
        self.assertEquals(int(self.values['struct_c.e']), c.e)
        
        return 


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    #logging.basicConfig(level=logging.INFO)    
    unittest.main(verbosity=2)

