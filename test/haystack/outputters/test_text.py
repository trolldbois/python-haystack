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
                k,v = fields[0],' '.join(fields[1:]).strip()
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

class TestTextOutput(SrcTests):
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

    def test_complex_text(self):
        from test.src import ctypes5_gen32
        model.registerModule(ctypes5_gen32)
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.mappings.getMmapForAddr(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        parser = text.RecursiveTextOutputter(self.mappings)
        out = parser.parse(d) 
        import code
        code.interact(local=locals())

        self.assertEquals(int(self.sizes['struct_d']), ctypes.sizeof(d))
        self.assertEquals(None, obj.a)
        self.assertEquals(int(self.values['struct_d.b.e']), obj.b.e)
        self.assertEquals(int(self.values['struct_d.b2.e']), obj.b2.e)
        for i in range(9):
            self.assertEquals(int(self.values['struct_d.c[%d].a'%(i)]), obj.c[i].a)
            self.assertEquals(int(self.values['struct_d.f[%d]'%(i)]), obj.f[i])
        self.assertEquals(int(self.values['struct_d.e']), obj.e)
        self.assertEquals(str(self.values['struct_d.i']), obj.i)
        return 





if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)

