#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import argparse

from haystack import dump_loader
from haystack import argparse_utils
from haystack.outputters import text



# from haystack.outputters import python

"""
Search for HEAP.
"""

log = logging.getLogger('haytack-find-heap')


def main(argv):
    parser = argparse.ArgumentParser(prog='haystack-find-heap',
                                          description="Find heaps in a dumpfile")
    parser.add_argument('--osname', '-n', action='store', default=None, choices=['winxp', 'win7'], help='winxp,win7')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')
    parser.add_argument('--quiet', dest='quiet', action='store_true', help='Set verbosity to ERROR only')
    parser.add_argument('--debug', '-d', dest='debug', action='store_true', help='Set verbosity to DEBUG')
    parser.add_argument('dumpname', type=argparse_utils.readable, help='process memory dump name')
    parser.add_argument('address', nargs='?', type=argparse_utils.int16, default=None, help='Load Heap from address (hex)')

    opts = parser.parse_args(argv)
    from haystack import cli
    cli.set_logging_level(opts)

    #
    memory_handler = dump_loader.load(opts.dumpname, os_name=opts.osname)
    finder = memory_handler.get_heap_finder()

    # Show Target information
    print memory_handler.get_target_platform()

    if opts.address is not None:
        one_heap(opts, finder)
        return

    if opts.verbose:
        # show all memory mappings
        print 'Process mappings:'
        print '@start     @stop       File Offset M:m   '
        for m in memory_handler.get_mappings():
            print m

    print 'Probable Process HEAPS:'
    for m in memory_handler.get_mappings():
        for addr in range(m.start, m.end, 0x1000):
            heap_not_at_start = ''
            heap = finder._read_heap(m, addr)
            # print hex(heap.Signature)
            if heap.Signature == 0xeeffeeff:
                if addr != m.start:
                    heap_not_at_start = ' (!) '
                print '[+] %s@0x%0.8x' % (heap_not_at_start, addr), m

    # Then show heap analysis
    print 'Found Heaps:'

    # TODO why not use native heap mappings searcher ?
    results = finder.search_heap()
    for ctypes_heap, addr in results:
        m = memory_handler.get_mapping_for_address(addr)
        validator = finder.get_heap_validator()
        validator.print_heap_analysis(ctypes_heap, opts.verbose)

    return


def one_heap(opts, finder):
    address = opts.address
    # just return the heap
    ctypes_heap, valid = finder.search_heap_direct(address)
    if opts.verbose:
        out = text.RecursiveTextOutputter(finder._memory_handler)
        # out = python.PythonOutputter(finder._memory_handler)
        print out.parse(ctypes_heap, depth=1)
    print 'Valid =', valid
    # fake it
    m = finder._memory_handler.get_mapping_for_address(address)
    m.mark_as_heap(address)
    validator = finder.get_heap_validator()
    validator.print_heap_analysis(ctypes_heap, opts.verbose)
    return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.DEBUG)
    main(sys.argv[1:])

