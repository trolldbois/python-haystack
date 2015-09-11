#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import sys
import argparse

from functools import partial

import haystack
from haystack import dump_loader
from haystack import constraints
from haystack import argparse_utils
from haystack.search import searcher
from haystack.outputters import text
#from haystack.outputters import python

"""
Search for HEAP.
"""

log = logging.getLogger('haytack-find-heap')


class HeapFinder(object):
    def __init__(self):
        print 'Using %s' % self.__class__.__name__
        pass

    def _init_module_name(self, memory_handler):
        raise NotImplementedError('_init_module_name')

    def _init_constraints_filename(self, heap_module):
        raise NotImplementedError('_init_constraints_filename')

    def _init_heap_record_name(self):
        raise NotImplementedError('_init_heap_record_name')

    def search_heap(self, memdumpname):
        # we need a memory dump loader
        self.memory_handler = dump_loader.load(memdumpname)
        my_model = self.memory_handler.get_model()
        module_name = self._init_module_name(self.memory_handler)
        # import the module with the right arch
        heap_module = my_model.import_module(module_name)
        log.debug('the heap module loaded is %s', module_name)
        # load the constraints
        constraint_filename = self._init_constraints_filename(heap_module)
        parser = constraints.ConstraintsConfigHandler()
        my_constraints = parser.read(constraint_filename)
        my_searcher = searcher.AnyOffsetRecordSearcher(self.memory_handler,
                                                       my_constraints,
                                                       update_cb=partial(self.print_cb, self.memory_handler))
        ## DEBUG
        # DEBUG PEB search
        #peb = my_model.import_module('haystack.structures.win32.winxp_32_peb')
        ##DEBUG
        heap_record_name = self._init_heap_record_name()
        heap_struct = getattr(heap_module, heap_record_name)
        # on ly return first results in each mapping
        results = []
        for mapping in self.memory_handler.get_mappings():
            log.debug("looking at %s", mapping)
            res = my_searcher._search_in(mapping, heap_struct, nb=1, align=0x1000)
            # DEBUG PEB search
            #res = my_searcher._search_in(mapping, peb.struct__PEB, nb=1, align=0x1000)
            if res:
                # FIXME output_to are stupid
                #print haystack.output_to_string(memory_handler, res)
                results.append(res)
        return results

    def search_heap_direct(self, memdumpname, start_address_mapping):
        # we need a memory dump loader
        self.memory_handler = dump_loader.load(memdumpname)
        my_model = self.memory_handler.get_model()
        module_name = self._init_module_name(self.memory_handler)
        # import the module with the right arch
        heap_module = my_model.import_module(module_name)
        log.debug('the heap module loaded is %s', module_name)
        # load the constraints
        constraint_filename = self._init_constraints_filename(heap_module)
        parser = constraints.ConstraintsConfigHandler()
        my_constraints = parser.read(constraint_filename)
        m = self.memory_handler.get_mapping_for_address(start_address_mapping)
        my_searcher = searcher.AnyOffsetRecordSearcher(self.memory_handler,
                                                       my_constraints,
                                                       [m],
                                                       update_cb=partial(self.print_cb, self.memory_handler))
        heap_record_name = self._init_heap_record_name()
        heap_struct = getattr(heap_module, heap_record_name)
        results = my_searcher._load_at(m, start_address_mapping, heap_struct, depth=5)
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
        for x, addr in py_results:
            heap_not_at_start = ' '
            m = memory_handler.get_mapping_for_address(addr)
            if addr != m.start:
                heap_not_at_start = ' (!)'
            print 'HEAP at 0x%x%s\tsize: 0x%x map: %s' % (addr, heap_not_at_start, len(m), m)
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

    def _init_heap_record_name(self):
        return 'HEAP'

class WinXPHeapFinder(HeapFinder):
    def _init_module_name(self, memory_handler):
        if 64 == memory_handler.get_target_platform().get_cpu_bits():
            module_name = 'haystack.structures.win32.winxp_64'
        else:
            module_name = 'haystack.structures.win32.winxp_32'
        return module_name

    def _init_constraints_filename(self, heap_module):
        return os.path.join(os.path.dirname(heap_module.__file__), 'winxpheap.constraints')

    def _init_heap_record_name(self):
        return 'HEAP'

class LibcHeapFinder(HeapFinder):
    def _init_module_name(self, memory_handler):
        module_name = 'haystack.structures.libc.ctypes_malloc'
        log.error("this doesn't not work on libc heap")
        return module_name

    def _init_constraints_filename(self, heap_module):
        return os.path.join(os.path.dirname(heap_module.__file__), 'libcheap.constraints')

    def _init_heap_record_name(self):
        return 'malloc_chunk'


def main(argv):
    parser = argparse.ArgumentParser(prog='haystack-find-heap',
                                          description="Find heaps in a dumpfile")
    parser.add_argument('--host', action='store', default='winxp', help='winxp,win7')
    parser.add_argument('dumpname', type=argparse_utils.readable, help='process memory dump name')
    parser.add_argument('address', nargs='?', type=argparse_utils.int16, default=None, help='Load Heap from address (hex)')

    opts = parser.parse_args(argv)

    #if 'libc' == opts.host:
    #    my_finder = LibcHeapFinder()
    #el
    if 'winxp' == opts.host:
        my_finder = WinXPHeapFinder()
    elif 'win7' == opts.host:
        my_finder = Win7HeapFinder()
    else:
        raise ValueError('not such heap finder for %s' % opts.host)

    memdumpname = opts.dumpname
    if opts.address is None:
        if my_finder.search_heap(memdumpname) is not None:
            return
    else:
        address = opts.address
        # just return the heap
        ret = my_finder.search_heap_direct(memdumpname, address)
        out = text.RecursiveTextOutputter(my_finder.memory_handler)
        #out = python.PythonOutputter(my_finder.memory_handler)
        print out.parse(ret[0], depth=4)
        print 'Valid=', ret[1]
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    main(sys.argv[1:])

