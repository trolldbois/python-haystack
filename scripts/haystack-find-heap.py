# /bin/python
# -*- coding: utf-8 -*-

import logging
import os
import sys

from functools import partial

import haystack
from haystack import dump_loader
from haystack import constraints
from haystack.search import searcher

"""
Search for HEAP.
"""

log = logging.getLogger('haytack-find-heap')


class HeapFinder(object):
    def __init__(self):
        pass

    def _init_module_name(self, memory_handler):
        raise NotImplementedError('_init_module_name')

    def _init_constraints_filename(self, heap_module):
        raise NotImplementedError('_init_constraints_filename')

    def search_heap(self, memdumpname):
        # we need a memory dump loader
        memory_handler = dump_loader.load(memdumpname)
        my_model = memory_handler.get_model()
        module_name = self._init_module_name(memory_handler)
        # import the module with the right arch
        heap_module = my_model.import_module(module_name)
        log.debug('the heap module loaded is %s', module_name)
        # load the constraints
        constraint_filename = self._init_constraints_filename(heap_module)
        parser = constraints.ConstraintsConfigHandler()
        my_constraints = parser.read(constraint_filename)
        my_searcher = searcher.AnyOffsetRecordSearcher(memory_handler,
                                                       my_constraints,
                                                       update_cb=partial(self.print_cb, memory_handler))
        results = my_searcher.search(heap_module.HEAP)
        return results

    def search_heap_direct(self, memdumpname, start_address_mapping):
        # we need a memory dump loader
        memory_handler = dump_loader.load(memdumpname)
        my_model = memory_handler.get_model()
        module_name = self._init_module_name(memory_handler)
        # import the module with the right arch
        heap_module = my_model.import_module(module_name)
        log.debug('the heap module loaded is %s', module_name)
        # load the constraints
        constraint_filename = self._init_constraints_filename(heap_module)
        parser = constraints.ConstraintsConfigHandler()
        my_constraints = parser.read(constraint_filename)
        m = memory_handler.get_mapping_for_address(start_address_mapping)
        my_searcher = searcher.AnyOffsetRecordSearcher(memory_handler,
                                                       my_constraints,
                                                       [m],
                                                       update_cb=partial(self.print_cb, memory_handler))
        results = my_searcher._load_at(m, start_address_mapping, heap_module.HEAP, depth=5)
        #print haystack.output_to_python(memory_handler, [results])[0][0].toString()
        return results

    def print_cb(self, memory_handler, instance, address):
        """
        Callback function called by AnyOffsetRecordSearcher when an instance is found

        :param memory_handler:
        :param instance:
        :param address:
        :return:
        """
        py_results = haystack.output_to_python(memory_handler, [(instance, address)])
        for x in py_results:
            m = memory_handler.get_mapping_for_address(address)
            print 'HEAP at 0x%x size: 0x%x map: %s' % (address, len(m), m)
            #print x


class Win7HeapFinder(HeapFinder):
    def _init_module_name(self, memory_handler):
        if 64 == memory_handler.get_target_platform().get_cpu_bits():
            module_name = 'haystack.structures.win32.win7_64'
        else:
            module_name = 'haystack.structures.win32.win7_32'
        return module_name

    def _init_constraints_filename(self, heap_module):
        return os.path.join(os.path.dirname(heap_module.__file__), 'win7heap.constraints')

class WinXPHeapFinder(HeapFinder):
    def _init_module_name(self, memory_handler):
        if 64 == memory_handler.get_target_platform().get_cpu_bits():
            module_name = 'haystack.structures.win32.winxp_64'
        else:
            module_name = 'haystack.structures.win32.winxp_32'
        return module_name

    def _init_constraints_filename(self, heap_module):
        return os.path.join(os.path.dirname(heap_module.__file__), 'winxpheap.constraints')

'''
zeus.vmem.856.dump

0x00090000-0x00190000
0x00190000-0x001a0000
0x001a0000-0x001b0000
0x00350000-0x00360000
0x003b0000-0x003c0000
0x00c30000-0x00cb0000
0x00d60000-0x00d70000
0x00e20000-0x00e30000
0x00e80000-0x00e90000
0x7f6f0000-0x7f7f0000



DEBUG:basicmodel:ptr: UnusedUnCommittedRanges <class 'haystack.types.LP_4_struct__HEAP_UNCOMMMTTED_RANGE'> LP_4_struct__HEAP_UNCOMMMTTED_RANGE(3160606104) 0xbc630598 INVALID

'''


def main(argv):
    memdumpname = argv[1]
    # memdumpname, address = argv[1], int(argv[2], 16)

    #f = Win7HeapFinder()
    #f.search_heap(memdumpname)
    f = WinXPHeapFinder()
    f.search_heap(memdumpname)
    #f.search_heap_direct(memdumpname, 0x00860000)
    #f = Win7HeapFinder()
    #f.search_heap_direct(memdumpname, address)



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    main(sys.argv)

