# !/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import sys

from functools import partial

import haystack
from haystack import dump_loader
from haystack import constraints
from haystack.search import searcher
from haystack.outputters import text

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

        # on ly return first results in each mapping
        results = []
        for mapping in self.memory_handler.get_mappings():
            log.debug("looking at %s", mapping)
            res = my_searcher._search_in(mapping, heap_module.HEAP, nb=1, align=0x1000)
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



DEBUG:basicmodel:ptr: UnusedUnCommittedRanges <class 'haystack.types.LP_4_struct__HEAP_UNCOMMMTTED_RANGE'>
LP_4_struct__HEAP_UNCOMMMTTED_RANGE(3160606104) 0xbc630598 INVALID
for f in `ls /home/jal/outputs/vol/zeus.vmem.1668.dump` ; do echo $f; xxd /home/jal/outputs/vol/zeus.vmem.1668.dump/$f | head | grep -c "ffee ffee" ; done | grep -B1 "1$"

DEBUG:utils:obj._sub_addr_: 0xbc630598

'''



def main(argv):
    for f in [
              #Win7HeapFinder(),
              WinXPHeapFinder()
             ]:
        if len(argv) == 2:
            memdumpname = argv[1]
            if f.search_heap(memdumpname) is not None:
                break
        elif len(argv) == 3:
            memdumpname, address = argv[1], int(argv[2], 16)
            ret = f.search_heap_direct(memdumpname, address)
            out = text.RecursiveTextOutputter(f.memory_handler)
            print out.parse(ret[0]), ret[1]
            break

    #f.search_heap(memdumpname)
    #f = Win7HeapFinder()
    #f.search_heap_direct(memdumpname, address)



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    main(sys.argv)

