#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

from haystack.mappings.vol import VolatilityProcessMapper

from test.testfiles import zeus_1668_vmtoolsd_exe

log = logging.getLogger('test_vol')

#@unittest.skip('not ready')
class TestMapper(unittest.TestCase):
    """
    load zeus.vmem from https://code.google.com/p/volatility/wiki/MemorySamples
    The malware analysis cookbook
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_number_of_mappings(self):
        """ check the number of mappings on 3 processes """
        #check vad numbers with
        #vol.py -f /home/jal/outputs/vol/zeus.vmem -p 856 vadwalk |wc -l
        #5 headers lines to be removed from count
        #
        #analysis here:
        #https://malwarereversing.wordpress.com/2011/09/23/zeus-analysis-in-volatility-2-0/

        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 856
        # PID 856 has 176 _memory_handler
        mapper = VolatilityProcessMapper(f, pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 176)

        # testing that we can use the Mapper twice in a row, without breaking
        # volatility
        pid = 676
        # PID 676 has 118 _memory_handler
        mapper = VolatilityProcessMapper(f, pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 118)

        pid = 1668
        # PID 1668 has 159 _memory_handler
        mapper = VolatilityProcessMapper(f, pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 159)

    def test_is_heaps(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 1668
        mapper = VolatilityProcessMapper(f, pid)
        memory_handler = mapper.make_memory_handler()
        finder = memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()
        self.assertEquals(len(heaps), len(zeus_1668_vmtoolsd_exe.known_heaps))
        for addr, size in zeus_1668_vmtoolsd_exe.known_heaps:
            heap = memory_handler.get_mapping_for_address(addr)
            self.assertTrue(heap.is_marked_as_heap())
            heap_addr = heap.get_marked_heap_address()
            self.assertTrue(heap_addr is not None)
            self.assertTrue(finder._is_heap(heap, heap_addr))


    def test_heaps(self):
        """ look for heaps in pid 856 """
        ''' for x in _memory_handler:
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
        # PID 856 has 176 _memory_handler
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.make_memory_handler()

        from haystack.structures.win32 import winxpheap
        for mstart in heaps:
            heap = mappings.get_mapping_for_address(mstart)
            res = heap.read_struct(heap.start,winxpheap.HEAP)
            self.assertTrue(res.is_valid(mappings))

        # testing that the list of heaps is always the same
        finder = mappings.get_heap_finder()
        self.assertEquals(set(heaps), set([m.start for m in finder.get_heap_mappings()]))
        return

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888  # wscntfy.exe
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.make_memory_handler()
        self.assertEquals(len(mappings), 51)
        self.assertEquals(mappings.get_os_name(), 'winxp')

        ctypes = mappings.config.ctypes
        from haystack.structures.win32 import winxpheap
        #print ctypes
        for m in mappings.mappings:
            data = m.read_word(m.start + 8)
            if data == 0xeeffeeff:
                # we have a heap
                x = m.read_struct(m.start, winxpheap.HEAP)
                print x

        self.assertEquals( ctypes.sizeof(x), 1430)
        # print x
        finder = mappings.get_heap_finder()
        heaps = finder.get_heap_mappings()
        #code.interact(local=locals())

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888  # wscntfy.exe
        mapper = VolatilityProcessMapper(f, pid)
        mappings = mapper.make_memory_handler()


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(logging.INFO)
    # logging.getLogger('model').setLevel(logging.INFO)
    # logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)
