#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

from haystack.mappings.vol import VolatilityProcessMapper

from test.testfiles import zeus_1668_vmtoolsd_exe
from test.testfiles import zeus_856_svchost_exe

log = logging.getLogger('test_vol')

#@unittest.skip('not ready')
class TestMapper(unittest.TestCase):
    """
    load zeus.vmem from https://code.google.com/p/volatility/wiki/MemorySamples
    The malware analysis cookbook
    """

    def setUp(self):
        try:
            import volatility
        except ImportError as e:
            self.skipTest('Volatility not installed')
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
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 176)

        # testing that we can use the Mapper twice in a row, without breaking
        # volatility
        pid = 676
        # PID 676 has 118 _memory_handler
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 118)

        pid = 1668
        # PID 1668 has 159 _memory_handler
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 159)

    def test_is_heaps_1168(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 1668
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        finder = memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        self.assertEquals(len(walkers), len(zeus_1668_vmtoolsd_exe.known_heaps))
        for addr, size in zeus_1668_vmtoolsd_exe.known_heaps:
            heap_mapping = memory_handler.get_mapping_for_address(addr)
            heap_walker = finder.get_heap_walker(heap_mapping)
            self.assertIsNotNone(heap_walker)
            heap_addr = heap_walker.get_heap_address()
            self.assertEqual(heap_addr, addr)

    @unittest.skip('number of heaps is still a open question')
    def test_is_heaps_856(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 856
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        finder = memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        self.assertEquals(len(walkers), len(zeus_856_svchost_exe.known_heaps))
        for addr, size in zeus_856_svchost_exe.known_heaps:
            heap_walker = finder.get_heap_walker(addr)
            self.assertIsNotNone(heap_walker)
            heap_addr = heap_walker.get_heap_address()
            self.assertEqual(heap_addr, addr)

    def test_read_mem(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 888  # wscntfy.exe
        mapper = VolatilityProcessMapper(f, "WinXPSP2x86", pid)
        memory_handler = mapper.make_memory_handler()
        self.assertEquals(len(memory_handler.get_mappings()), 51)
        self.assertEquals(memory_handler.get_target_platform().get_os_name(), 'winxp')

        ctypes = memory_handler.get_target_platform().get_target_ctypes()
        from haystack.allocators.win32 import winxp_32
        #print ctypes
        for m in memory_handler.get_mappings():
            data = m.read_word(m.start + 8)
            if data == 0xeeffeeff:
                # we have a heap
                x = m.read_struct(m.start, winxp_32.HEAP)
                #print x

        self.assertEquals(ctypes.sizeof(x), 1416)
        # print x
        finder = memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        #code.interact(local=locals())



if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(logging.INFO)
    # logging.getLogger('model').setLevel(logging.INFO)
    # logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)
