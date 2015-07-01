#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import sys
import unittest

from haystack import model
from haystack import types
from haystack.mappings.vol import VolatilityProcessMapper
from haystack.mappings.vol import VolatilityProcessMapping

log = logging.getLogger('test_vol')

#@unittest.skip("work needed")
class TestMapper(unittest.TestCase):
    '''load zeus.vmem from https://code.google.com/p/volatility/wiki/MemorySamples 
    The malware analysis cookbook'''

    def setUp(self):
        model.reset()

    def tearDown(self):
        model.reset()
        types.load_ctypes_default()


    def test_init(self):
        ''' check vad numbers with 
        vol.py -f /home/jal/outputs/vol/zeus.vmem -p 856 vadwalk |wc -l 
        5 headers lines to be removed from count
        
        analysis here:
        https://malwarereversing.wordpress.com/2011/09/23/zeus-analysis-in-volatility-2-0/
        '''
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 856
        # PID 856 has 176 mappings
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.getMappings()
        self.assertEquals(len(mappings), 176)

        # testing that we can use the Mapper twice in a row, without breaking
        # volatility
        pid = 676
        # PID 676 has 118 mappings
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.getMappings()
        self.assertEquals(len(mappings), 118)


    def test_heaps(self):
        ''' look for heaps in pid 856'''
        ''' for x in mappings:
                res = x.readStruct(x.start,winheap.HEAP)
                if res.Signature == 0xeeffeeffL:
                    print x.start, "Signature:", hex(res.Signature)
0x190000L Signature: 0xeeffeeffL
0x90000L Signature: 0xeeffeeffL
0x1a0000L Signature: 0xeeffeeffL
0x350000L Signature: 0xeeffeeffL
0x3b0000L Signature: 0xeeffeeffL
0xc30000L Signature: 0xeeffeeffL
0xd60000L Signature: 0xeeffeeffL
0xe20000L Signature: 0xeeffeeffL
0xe80000L Signature: 0xeeffeeffL
0x7f6f0000L Signature: 0xeeffeeffL'''
        heaps = [0x190000L,0x90000L,0x1a0000L,0x350000L,0x3b0000L,0xc30000L,
                 0xd60000L,0xe20000L,0xe80000L,0x7f6f0000L]
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 856
        # PID 856 has 176 mappings
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.getMappings()

        from haystack.structures.win32 import winheap
        for mstart in heaps:
            heap = mappings.get_mapping_for_address(mstart)
            res = heap.readStruct(heap.start,winheap.HEAP)
            self.assertTrue(res.isValid(mappings))

        # testing that the list of heaps is always the same
        self.assertEquals(set(heaps), set([m.start for m in mappings.get_heaps()]))
        return

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888  # wscntfy.exe
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.getMappings()
        self.assertEquals(len(mappings), 51)
        self.assertEquals(mappings.get_os_name(), 'winxp')

        ctypes = mappings.config.ctypes
        from haystack.structures.win32 import winheap
        #print ctypes
        import pefile
        import code
        for m in mappings.mappings:
            data = m.readWord(m.start + 8)
            if data == 0xeeffeeff:
                # we have a heap
                x = m.readStruct(m.start, winheap.HEAP)
                print x

        self.assertEquals( ctypes.sizeof(x), 1430)
        # print x

        heaps = mappings.get_heaps()
        #code.interact(local=locals())

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888  # wscntfy.exe
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.getMappings()


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(logging.INFO)
    # logging.getLogger('model').setLevel(logging.INFO)
    # logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)
