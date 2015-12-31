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



def count_by_mapping(memory_handler, chunksize_tuple, overhead_size):
    res = {}
    for addr, size in chunksize_tuple:
        m = memory_handler.get_mapping_for_address(addr)
        if m not in res:
            # (size,overhead)
            res[m] = (0, 0)
        tsize, overhead = res[m]
        tsize += size
        overhead += overhead_size # size of win chunk header
        res[m] = (tsize, overhead)
    return res


def count_by_segment(segment_list, chunksize_tuple, overhead_size):
    res = {}
    for addr, size in chunksize_tuple:
        for s in segment_list:
            if s.FirstEntry.value <= addr <= s.LastValidEntry.value:
                # we found the segment
                key = s.FirstEntry.value
                if key not in res:
                    # (size,overhead)
                    res[key] = (0, 0)
                tsize, overhead = res[key]
                tsize += size
                overhead += overhead_size # size of win chunk header
                res[key] = (tsize, overhead)
                break
    return res


def main(argv):
    parser = argparse.ArgumentParser(prog='haystack-find-heap',
                                          description="Find heaps in a dumpfile")
    parser.add_argument('--host', action='store', default='winxp', help='winxp,win7')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose')
    parser.add_argument('dumpname', type=argparse_utils.readable, help='process memory dump name')
    parser.add_argument('address', nargs='?', type=argparse_utils.int16, default=None, help='Load Heap from address (hex)')

    opts = parser.parse_args(argv)

    # we need a memory dump loader
    memory_handler = dump_loader.load(opts.dumpname)

    from haystack.outputters import text
    from haystack.allocators.win32 import winheap
    output = text.RecursiveTextOutputter(memory_handler)

    my_finder = memory_handler.get_heap_finder()

    # Show Target information
    print memory_handler.get_target_platform()

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
            heap = my_finder._read_heap(m, addr)
            # print hex(heap.Signature)
            if heap.Signature == 0xeeffeeff:
                if addr != m.start:
                    heap_not_at_start = ' (!) '
                print '[+] %s@0x%0.8x' % (heap_not_at_start, addr), m

    # Then show heaps
    print 'Found Heaps:'

    results = my_finder.search_heap()
    for ctypes_heap, addr in results:
        heap_not_at_start = ''
        m = memory_handler.get_mapping_for_address(addr)
        if addr != m.start:
            heap_not_at_start = ' (!) '

        print '[+] %s@0x%0.8x' % (heap_not_at_start, addr), m
        if not opts.verbose:
            continue
        #print x
        # print children

        ## KEEP
        # Mark as heap for later use
        m.mark_as_heap(addr)


        #
        finder = memory_handler.get_heap_finder()
        walker = finder.get_heap_walker(m)
        validator = walker._validator

        ## size & space calculated from chunks
        ### TODO: user allocations/free_chunks should be done on segments ?
        # is there where the empty space is ?

        ## size & space calculated from heap info
        ucrs = validator.HEAP_get_UCRanges_list(walker._heap)
        ucr_info = winheap.UCR_List(ucrs)
        # walker._heap.Counters.TotalMemoryReserved.value == walker._heap.LastValidEntry.value-walker._heap.BaseAddress.value
        nb_ucr = walker._heap.Counters.TotalUCRs
        print '\tUCRList: %d/%d' % (len(ucrs), nb_ucr)
        print ucr_info.to_string('\t\t')

        # heap is a segment
        segments = validator.HEAP_get_segment_list(walker._heap)
        nb_segments = walker._heap.Counters.TotalSegments

        overhead_size = memory_handler.get_target_platform().get_target_ctypes().sizeof(validator.win_heap.struct__HEAP_ENTRY)
        # get allocated/free stats by mappings
        occupied_res = count_by_mapping(memory_handler, walker.get_user_allocations(), overhead_size)
        free_res = count_by_mapping(memory_handler, walker.get_free_chunks(), overhead_size)
        # get allocated/free stats by segment
        occupied_res2 = count_by_segment(segments, walker.get_user_allocations(), overhead_size)
        free_res2 = count_by_segment(segments, walker.get_free_chunks(), overhead_size)

        print "\tSegmentList: %d/%d" % (len(segments), nb_segments)
        #print ".SegmentList.Flink", hex(walker._heap.SegmentList.Flink.value)
        #print ".SegmentList.Blink", hex(walker._heap.SegmentList.Blink.value)
        #print ".SegmentListEntry.Flink", hex(walker._heap.SegmentListEntry.Flink.value)
        #print ".SegmentListEntry.Blink", hex(walker._heap.SegmentListEntry.Blink.value)
        for segment in segments:
            p_segment = winheap.Segment(memory_handler, segment, ucrs)
            p_segment.set_ressource_usage(occupied_res2, free_res2)
            print p_segment.to_string('\t\t')
            # if UCR, then
            ucrsegments = validator.get_UCR_segment_list(segment)
            print "\t\t\tUCRSegmentList: %d {%s}" % (len(ucrsegments), ','.join(sorted([hex(s._orig_address_) for s in ucrsegments])))
            #print ".UCRSegmentList.Flink", hex(walker._heap.UCRSegmentList.Flink.value)
            #print ".UCRSegmentList.Blink", hex(walker._heap.UCRSegmentList.Blink.value)
            #

        # look at children from free/allocations POV
        children = walker.get_heap_children_mmaps()
        print ''
        for child in children:
            print '\t[-] ', child
            allocated, allocated_overhead = occupied_res.get(child, (0, 0))
            free, free_overhead = free_res.get(child, (0, 0))
            overhead = allocated_overhead + free_overhead
            sum_ = allocated + free + overhead
            print "\ta:0x%0.8x \tf:0x%0.8x \to:0x%0.8x Sum:0x%0.8x" % (allocated, free, overhead, sum_)

        #logging.getLogger("listmodel").setLevel(logging.DEBUG)


        output = text.RecursiveTextOutputter(memory_handler)
        # print output.parse(walker._heap.Counters)
        import code
        code.interact(local=locals())




    if opts.address is not None:
        one_heap(opts, my_finder)
    return


def one_heap(opts, my_finder):
    address = opts.address
    # just return the heap
    ret = my_finder.search_heap_direct(address)
    out = text.RecursiveTextOutputter(my_finder.memory_handler)
    #out = python.PythonOutputter(my_finder.memory_handler)
    print out.parse(ret[0], depth=4)
    print 'Valid=', ret[1]
    return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.DEBUG)
    main(sys.argv[1:])

