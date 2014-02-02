#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import unittest
import logging

from haystack import model
from haystack.mappings.vol import VolatilityProcessMapper
from haystack.mappings.vol import VolatilityProcessMapping

log = logging.getLogger('test_vol')


class TestMapper(unittest.TestCase):
    def setUp(self):    
        model.reset()

    def test_init(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 676 # services
        #pid = 124 #cmd
        mapper = VolatilityProcessMapper(f,pid)
        mappings = mapper.getMappings()
        self.assertEquals(len(mappings), 118)
        #import code
        #code.interact(local=locals())

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888 # wscntfy.exe
        mapper = VolatilityProcessMapper(f,pid)
        mappings = mapper.getMappings()
        self.assertEquals(len(mappings), 51)
        self.assertEquals(mappings.get_target_system(), 'win32')
        
        from haystack.structures.win32 import win7heap
        import ctypes
        print ctypes
        import pefile
        import code
        m = [ m for m in mappings.mappings if 'wscntfy.exe' in m.pathname][0]
        x = m.readBytes(m.start,0x1000)
        
        print win7heap.HEAP.Signature 
        x = win7heap.HEAP.from_buffer_copy(buf)
        self.assertEquals(len(win7heap.HEAP()), 312)

        heaps = mappings.getHeaps()
        #code.interact(local=locals())


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    #logging.getLogger('basicmodel').setLevel(logging.INFO)
    #logging.getLogger('model').setLevel(logging.INFO)
    #logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)


