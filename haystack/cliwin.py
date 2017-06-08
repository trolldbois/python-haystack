#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import logging
import sys
import argparse

from haystack import dump_loader
from haystack import argparse_utils
from haystack.outputters import text
import struct



# from haystack.outputters import python

"""
Search for HEAP.
"""

log = logging.getLogger('cliwin')


def find_heap():
    argv = sys.argv[1:]
    parser = argparse.ArgumentParser(prog='haystack-find-heap',
                                          description="Find heaps in a dumpfile")
    parser.add_argument('--osname', '-n', action='store', default=None, choices=['winxp', 'win7'], help='winxp,win7')
    parser.add_argument('--bits', '-b', type=int, action='store', default=None, choices=[32, 64], help='32,64')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')
    parser.add_argument('--quiet', action='store_true', help='Set verbosity to ERROR only')
    parser.add_argument('--debug', '-d', action='store_true', help='Set verbosity to DEBUG')
    parser.add_argument('--mappings', '-m', action='store_true', help='Show mappings')
    parser.add_argument('--heap', '-p', action='store_true', help='Show the heap content')
    parser.add_argument('--frontend', '-f', action='store_true', help='Show the frontend heap content')
    parser.add_argument('dumpname', type=argparse_utils.readable, help='process memory dump name')
    parser.add_argument('address', nargs='?', type=argparse_utils.int16, default=None, help='Load Heap from address (hex)')

    opts = parser.parse_args(argv)
    from haystack import cli
    cli.set_logging_level(opts)

    #
    memory_handler = dump_loader.load(opts.dumpname, os_name=opts.osname, cpu=opts.bits)
    finder = memory_handler.get_heap_finder()

    # Show Target information
    if opts.bits or opts.osname:
        print('Forced target resolution:', memory_handler.get_target_platform())
    else:
        print('Automatic target resolution:', memory_handler.get_target_platform())

    if opts.mappings:
        # show all memory mappings
        print('Process mappings:')
        print('@start     @stop       File Offset M:m   ')
        for m in memory_handler.get_mappings():
            print(m)

    if opts.address is not None:
        one_heap(opts, finder)
        return

    print('Probable Process HEAPS:')
    for m in memory_handler.get_mappings():
        for addr in range(m.start, m.end, 0x1000):
            special = ''
            for os, bits, offset in [('winxp', 32, 8), ('winxp', 64, 16),
                                     ('win7', 32, 100), ('win7', 64, 160)]:
                signature = struct.unpack('I', m.read_bytes(addr+offset, 4))[0]
                if signature == 0xeeffeeff:
                    if addr != m.start:
                        special = ' (!) '
                    print('[+] %s %dbits  %s 0x%0.8x' % (os, bits, special, addr), m)

    # Then show heap analysis
    print('Found Heaps:')

    for walker in finder.list_heap_walkers():
        validator = walker.get_heap_validator()
        validator.print_heap_analysis(walker.get_heap(), opts.verbose)

    return


def one_heap(opts, finder):
    address = opts.address
    memory_handler = finder._memory_handler
    # just return the heap
    ctypes_heap, valid = finder.search_heap_direct(address)
    out = text.RecursiveTextOutputter(finder._memory_handler)
    # out = python.PythonOutputter(finder._memory_handler)
    if opts.heap:
        print(out.parse(ctypes_heap, depth=2))
        print('Valid =', valid)
    if opts.frontend:
        heap_addr = ctypes_heap._orig_address_
        heap_m = memory_handler.get_mapping_for_address(heap_addr)
        walker = finder.get_heap_walker(heap_m)
        win_heap = walker._heap_module
        _utils = memory_handler.get_target_platform().get_target_ctypes_utils()
        if ctypes_heap.FrontEndHeapType == 0:
            log.error('BACKEND HEAP Type')
        elif ctypes_heap.FrontEndHeapType == 1:
            lal_start_addr = _utils.get_pointee_address(ctypes_heap.FrontEndHeap)
            m = memory_handler.is_valid_address(lal_start_addr, win_heap.HEAP_LOOKASIDE * 128)
            if not m:
                log.error('HEAP.FrontEndHeap has a bad address %x', lal_start_addr)
                return set()
            lal_list = m.read_struct(lal_start_addr, win_heap.HEAP_LOOKASIDE * 128)
            for i, st in enumerate(lal_list):
                out.parse(st, depth=2)
        elif ctypes_heap.FrontEndHeapType == 2 and memory_handler.get_target_platform().get_os_name() != 'winxp':
            lfh_start_addr = _utils.get_pointee_address(ctypes_heap.FrontEndHeap)
            m = memory_handler.is_valid_address(lfh_start_addr, win_heap.LFH_HEAP)
            if not m:
                log.error('HEAP.FrontEndHeap has a bad address %x', lfh_start_addr)
                return set()
            lfh_heap = m.read_struct(lfh_start_addr, win_heap.LFH_HEAP)
            out.parse(lfh_heap, depth=2)

        pass
    # fake it
    if valid:
        m = memory_handler.get_mapping_for_address(address)
        # we force the mapping to be a heap container because we where asked to
        validator = finder.get_heap_walker(m).get_heap_validator()
        validator.print_heap_analysis(ctypes_heap, opts.verbose)
    else:
        print("Could not load Heap for target", memory_handler.get_target_platform())
    return


if __name__ == '__main__':
    find_heap()

