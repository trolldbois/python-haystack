#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import pickle
# import dill as pickle
import time
import numpy
import os

from haystack.abc import interfaces
from haystack.reverse import utils
from haystack.reverse import config
from haystack.reverse import structure
from haystack.reverse import searchers
from haystack.reverse import matchers
from haystack.reverse import enumerators


log = logging.getLogger('context')


class ProcessContext(object):
    """
    The main context for all heap
    """
    def __init__(self, memory_handler):
        self.memory_handler = memory_handler
        # init heaps
        self.__contextes = {}
        for heap in self.memory_handler.get_heap_finder().get_heap_mappings():
            self.get_context_for_heap(heap)
        # init reversed types
        self.__reversed_types = {}
        self.__record_graph = None
        # see bug #17 self.__model = model.Model(self.memory_handler)
        # no need for that
        # create the cache folder then
        self.create_cache_folder()

    # def get_functions_pointers(self):
    #     try:
    #         return self.get_cache_radare()
    #     except IOError as e:
    #         return self.save_cache_radare()
    #
    # def get_cache_radare(self):
    #     dumpname = self.memory_handler.get_name()
    #     fname = config.get_cache_filename(config.CACHE_FUNCTION_NAMES, dumpname)
    #     functions = None
    #     try:
    #         with file(fname, 'r') as fin:
    #             functions = pickle.load(fin)
    #     except EOFError as e:
    #         os.remove(fname)
    #         log.error('Error in the radare cache file. File cleaned. Please restart.')
    #         raise RuntimeError('Error in the radare cache file. File cleaned. Please restart.')
    #     return functions
    #
    # def save_cache_radare(self):
    #     from haystack.reverse.heuristics import radare
    #     func = radare.RadareAnalysis(self.memory_handler)
    #     func.init_all_functions()
    #     import code
    #     code.interact(local=locals())
    #     dumpname = self.memory_handler.get_name()
    #     fname = config.get_cache_filename(config.CACHE_FUNCTION_NAMES, dumpname)
    #     with file(fname, 'w') as fout:
    #         pickle.dump(func.functions, fout)
    #     return func.functions

    def create_cache_folder(self):
        """Removes the cache folder"""
        dumpname = self.memory_handler.get_name()
        # create the cache folder
        cache_folder = config.get_cache_folder_name(dumpname)
        # config.remove_cache_folder(self.memory_handler.get_name())
        if not os.access(cache_folder, os.F_OK):
            os.mkdir(cache_folder)
            log.info("[+] Cache created in %s", cache_folder)
        else:
            log.debug("[+] Cache exists in %s", cache_folder)
        # and the record subfolder
        self.create_record_cache_folder()

    def create_record_cache_folder(self):
        # and the record subfolder
        dumpname = self.memory_handler.get_name()
        record_cache = config.get_record_cache_folder_name(dumpname)
        if not os.access(record_cache, os.F_OK):
            os.mkdir(record_cache)
            log.info("[+] Record cache created in %s", record_cache)
        else:
            log.debug("[+] Record cache exists in %s", record_cache)

    def _set_context_for_heap(self, mmap, ctx):
        """Caches the HeapContext associated to a IMemoryMapping"""
        self.__contextes[mmap.get_marked_heap_address()] = ctx

    def get_context_for_heap(self, heap):
        """Returns the HeapContext associated to a IMemoryMapping"""
        if not isinstance(heap, interfaces.IMemoryMapping):
            raise TypeError('heap should be a IMemoryMapping')
        if not heap.is_marked_as_heap():
            raise TypeError('heap should be a heap: %s', heap)
        if heap.get_marked_heap_address() not in self.__contextes:
            heap_context = self.make_context_for_heap(heap)
            self._set_context_for_heap(heap, heap_context)
            return heap_context
        return self.__contextes[heap.get_marked_heap_address()]

    def make_context_for_heap(self, heap):
        """
        Make the HeapContext for this heap.
        This will reverse all user allocations from this HEAP into records.
        """
        heap_addr = heap.get_marked_heap_address()
        try:
            ctx = HeapContext.cacheLoad(self.memory_handler, heap_addr)
            log.debug("Cache avoided HeapContext initialisation")
        except IOError as e:
            # heaps are already generated at initialisation of self
            heap = self.memory_handler.get_mapping_for_address(heap_addr)
            ctx = HeapContext(self.memory_handler, heap)
        return ctx

    def list_contextes(self):
        """Returns all known HeapContext"""
        return self.__contextes.values()

    def get_reversed_type(self, typename):
        if typename in self.__reversed_types:
            return self.__reversed_types[typename]
        return None

    def add_reversed_type(self, typename, t):
        self.__reversed_types[typename] = t

    def list_reversed_types(self):
        return self.__reversed_types.keys()

    #def _load_reversed_types(self):
    #    self.__reversed_types = pickle.load()

    def save_reversed_types(self):
        """
        Save the python class code definition to file.
        """
        fout = open(self.get_filename_cache_headers(), 'w')
        towrite = []
        #
        for r_type in self.list_reversed_types():
            members = self.get_reversed_type(r_type)
            from haystack.reverse.heuristics import constraints
            rev = constraints.ConstraintsReverser(self.memory_handler)
            txt = rev.verify(r_type, members)
            towrite.extend(txt)
            towrite.append("# %d members" % len(members))
            towrite.append(r_type.to_string())
            if len(towrite) >= 10000:
                try:
                    fout.write('\n'.join(towrite))
                except UnicodeDecodeError as e:
                    print 'ERROR on ', r_type
                towrite = []
                fout.flush()
        fout.write('\n'.join(towrite))
        fout.close()
        return

    def _load_graph_cache(self):
        from haystack.reverse.heuristics import reversers
        graph_rev = reversers.PointerGraphReverser(self.memory_handler)
        self.__record_graph = graph_rev.load_process_graph()

    def get_predecessors(self, record):
        """
        Returns the list of record pointing to this record.

        :param: record
        :return list
        """
        if self.__record_graph is None:
            self._load_graph_cache()
        predecessors_label = self.__record_graph.predecessors(hex(record.address))
        records = []
        for label in predecessors_label:
            if label[-1] == 'L':
                label = label[:-1]
            record_addr = int(label, 16)
            heap = self.memory_handler.get_mapping_for_address(record_addr)
            heap_context = self.get_context_for_heap(heap)
            records.append(heap_context.get_record_for_address(record_addr))
        return records

    def get_filename_cache_headers(self):
        dumpname = self.memory_handler.get_name()
        return config.get_cache_filename(config.CACHE_GENERATED_PY_HEADERS_VALUES, dumpname)


class HeapContext(object):
    """
    The HeapContext is a stateful instance around a Heap.
    The context contains cache helpers around the reversing of records.
    """

    def __init__(self, memory_handler, heap):
        self.memory_handler = memory_handler
        # cache it
        ### memory_handler.set_context_for_heap(heap, self)
        self.dumpname = memory_handler.get_name()
        self.heap = heap
        self._heap_start = heap.start
        self._function_names = dict()
        # refresh heap pointers list and allocators chunks
        self._reversedTypes = dict()
        self._structures = None
        self._init2()
        return

    def _init2(self):
        log.debug('[+] HeapContext on heap 0x%x', self.heap.get_marked_heap_address())
        # Check that cache folder exists
        if not os.access(config.get_cache_folder_name(self.dumpname), os.F_OK):
            os.mkdir(config.get_cache_folder_name(self.dumpname))
        # we need a heap walker to parse all allocations
        finder = self.memory_handler.get_heap_finder()
        heap_walker = finder.get_heap_walker(self.heap)

        log.debug('[+] Searching pointers in heap')
        # get all pointers found in from allocated space.
        all_offsets, all_values = self.get_heap_pointers_from_allocated(heap_walker)
        self._pointers_values = all_values
        self._pointers_offsets = all_offsets

        log.debug('[+] Gathering allocated heap chunks')
        res = utils.cache_get_user_allocations(self, heap_walker)
        self._structures_addresses, self._structures_sizes = res

        # clean a bit the open fd's
        self.memory_handler.reset_mappings()

        #if self.memory_handler.get_target_platform().get_os_name() not in ['winxp', 'win7']:
        #    log.info('[+] Reversing function pointers names')
        #    # TODO in reversers
        #    # dict(libdl.reverseLocalFonctionPointerNames(self) )
        #    self._function_names = dict()
        return

    def _is_record_cache_dirty(self):
        return self._structures is None or len(self._structures) != len(self._structures_addresses)

    # TODO implement a LRU cache
    def _list_records(self):
        if not self._is_record_cache_dirty():
            return self._structures

        # otherwise cache Load
        log.debug('[+] Loading cached records list')
        self._structures = dict([(long(vaddr), s) for vaddr, s in structure.cache_load_all_lazy(self)])
        log.debug('[+] Loaded %d cached records addresses from disk', len(self._structures))

        # If we are missing some allocators from the cache loading
        # then recreated them in cache from Allocated memory
        nb_missing = len(self._structures_addresses) - len(self._structures)
        if nb_missing != 0:
            from haystack.reverse.heuristics import reversers
            log.debug('[+] Missing cached records %d' % nb_missing)
            if nb_missing < 10:
                nb_unique = len(set(self._structures_addresses) - set(self._structures))
                log.warning('TO check missing:%d unique:%d', nb_missing, nb_unique)
            # use BasicCachingReverser to get user blocks
            cache_reverse = reversers.BasicCachingReverser(self.memory_handler)
            _ = cache_reverse.reverse_context(self)
            log.info('[+] Built %d/%d records from allocations',
                     len(self._structures),
                     len(self._structures_addresses))
        return self._structures

    def get_record_size_for_address(self, addr):
        """
        return the allocated record size associated with this address

        :param addr:
        :return:
        """
        itemindex = numpy.where(self._structures_addresses == numpy.int64(addr))[0][0]
        return self._structures_sizes[itemindex]

    def get_record_count(self):
        if self._is_record_cache_dirty():
            # refresh the cache
            return len(self._list_records())
        return len(self._structures_addresses)

    def get_record_address_at_address(self, _address):
        """
        Returns the closest containing record address for this address.
        :param _address:
        :return:
        """
        # if offset not in self.heap:
        #  raise ValueError('address 0x%0.8x not in heap 0x%0.8x'%(offset, self.heap.start))
        return utils.closestFloorValue(_address, self._structures_addresses)[0]  # [1] is the index of [0]

    def get_record_at_address(self, _address):
        """
        Returns the closest containing record for this address.
        :param _address:
        :return:
        """
        st = self.get_record_for_address(self.get_record_address_at_address(_address))
        if st.address <= _address < (st.address + len(st)):
            return st
        raise IndexError('No known structure covers that ptr_value')

    def get_record_for_address(self, addr):
        """
        return the structure.AnonymousRecord associated with this address

        :param addr:
        :return:
        """
        return self._list_records()[addr]

    def listOffsetsForPointerValue(self, ptr_value):
        '''Returns the list of offsets where this value has been found'''
        return [int(self._pointers_offsets[offset])
                for offset in numpy.where(self._pointers_values == ptr_value)[0]]

    def listPointerValueInHeap(self):
        '''Returns the list of pointers found in the heap'''
        return map(long, self._pointers_values)

    def listStructuresAddrForPointerValue(self, ptr_value):
        '''Returns the list of allocators addresses with a member with this pointer value '''
        return sorted(set([int(self.get_record_address_at_address(offset))
                           for offset in self.listOffsetsForPointerValue(ptr_value)]))

    def listStructuresForPointerValue(self, ptr_value):
        '''Returns the list of allocators with a member with this pointer value '''
        return [self._list_records()[addr]
                for addr in self.listStructuresAddrForPointerValue(ptr_value)]

    def list_allocations_addresses(self):
        return map(long, self._structures_addresses)

    def list_allocations_sizes(self):
        return map(long, self._structures_sizes)

    def listStructuresAddresses(self):
        return map(long, self._list_records().keys())

    def listStructures(self):
        return self._list_records().values()

    def is_known_address(self, address):
        return address in self._structures_addresses

    # name of cache files
    def get_folder_cache(self):
        return config.get_cache_folder_name(self.dumpname)

    def get_folder_cache_structures(self):
        return config.get_record_cache_folder_name(self.dumpname)

    def get_filename_cache_context(self):
        return config.get_cache_filename(config.CACHE_CONTEXT, self.dumpname, self._heap_start)

    def get_filename_cache_headers(self):
        return config.get_cache_filename(config.CACHE_GENERATED_PY_HEADERS_VALUES, self.dumpname, self._heap_start)

    def get_filename_cache_graph(self):
        return config.get_cache_filename(config.CACHE_GRAPH, self.dumpname, self._heap_start)

    def get_filename_cache_pointers_addresses(self):
        return config.get_cache_filename(config.CACHE_HEAP_ADDRS, self.dumpname, self._heap_start)

    def get_filename_cache_pointers_values(self):
        return config.get_cache_filename(config.CACHE_HEAP_VALUES, self.dumpname, self._heap_start)

    def get_filename_cache_allocations_addresses(self):
        return config.get_cache_filename(config.CACHE_MALLOC_CHUNKS_ADDRS, self.dumpname, self._heap_start)

    def get_filename_cache_allocations_sizes(self):
        return config.get_cache_filename(config.CACHE_MALLOC_CHUNKS_SIZES, self.dumpname, self._heap_start)

    def get_filename_cache_signatures(self):
        return config.get_cache_filename(config.CACHE_SIGNATURE_GROUPS_DIR, self.dumpname, self._heap_start)

    def get_heap_pointers(self):
        """
        @UNUSED

        Search Heap pointers values in stack and heap.
            records values and pointers address in heap.
        :param memory_handler:
        :param heap_walker:
        :return:
        """
        feedback = searchers.NoFeedback()
        matcher = matchers.PointerEnumerator(self.memory_handler)
        word_size = self.memory_handler.get_target_platform().get_word_size()
        enumerator = enumerators.WordAlignedEnumerator(self.heap, matcher, feedback, word_size)
        return utils.get_cache_heap_pointers(self, enumerator)

    def get_heap_pointers_from_allocated(self, heap_walker):
        """
        Search Heap pointers values in stack and heap.
            records values and pointers address in heap.
        :param dumpfilename:
        :param memory_handler:
        :param heap_walker:
        :return:
        """
        feedback = searchers.NoFeedback()
        matcher = matchers.PointerEnumerator(self.memory_handler)
        word_size = self.memory_handler.get_target_platform().get_word_size()
        enumerator = enumerators.AllocatedWordAlignedEnumerator(heap_walker, matcher, feedback, word_size)
        return utils.get_cache_heap_pointers(self, enumerator)

    @classmethod
    def cacheLoad(cls, memory_handler, heap_addr):
        dumpname = os.path.abspath(memory_handler.get_name())
        config.create_cache_folder_name(dumpname)
        context_cache = config.get_cache_filename(config.CACHE_CONTEXT, dumpname, heap_addr)
        try:
            with file(context_cache, 'r') as fin:
                ctx = pickle.load(fin)
        except EOFError as e:
            os.remove(context_cache)
            log.error('Error in the context file. File cleaned. Please restart.')
            raise RuntimeError('Error in the context file. File cleaned. Please restart.')
        log.debug('\t[-] loaded my context from cache')
        ctx.config = config
        ctx.memory_handler = memory_handler
        ctx.heap = ctx.memory_handler.get_mapping_for_address(ctx._heap_start)
        # and initialize
        ctx._init2()
        return ctx

    def save(self):
        # we only need dumpfilename to reload _memory_handler, addresses to reload
        # cached records
        cache_context_filename = self.get_filename_cache_context()
        try:
            with file(cache_context_filename, 'w') as fout:
                pickle.dump(self, fout)
        except pickle.PicklingError, e:
            log.error("Pickling error on %s, file removed", cache_context_filename)
            os.remove(cache_context_filename)
            raise e

    def reset(self):
        try:
            cache_context_filename = self.get_filename_cache_context()
            os.remove(cache_context_filename)
        except OSError as e:
            pass

    def __getstate__(self):
        d = dict()
        d['dumpname'] = self.__dict__['dumpname']
        d['_heap_start'] = self.__dict__['_heap_start']
        return d

    def __setstate__(self, d):
        self.dumpname = d['dumpname']
        self._heap_start = d['_heap_start']
        self._structures = None
        self._function_names = dict()
        return

    def save_structures(self):
        t0 = time.time()
        if self._structures is None:
            log.debug('No loading has been done, not saving anything')
            return
        # dump all allocators
        for i, s in enumerate(self._structures.values()):
            try:
                s.saveme(self)
            except KeyboardInterrupt as e:
                os.remove(s.fname)
                raise e
            if time.time() - t0 > 30:  # i>0 and i%10000 == 0:
                tl = time.time()
                rate = (tl - t0) / (1 + i)
                _ttg = (len(self._structures) - i) * rate
                log.info('\t\t - %2.2f seconds to go', _ttg)
                t0 = tl
        tf = time.time()
        log.info('\t[.] saved in %2.2f secs' % (tf - t0))


def get_context_for_address(memory_handler, address):
    """
    Returns the haystack.reverse.context.HeapContext of the process
    for the HEAP that hosts this address
    """
    assert isinstance(address, long) or isinstance(address, int)
    mmap = memory_handler.get_mapping_for_address(address)
    if not mmap:
        raise ValueError("Invalid address: 0x%x", address)
    finder = memory_handler.get_heap_finder()
    if mmap not in finder.get_heap_mappings():
        # addr is not a heap addr,
        found = False
        # or its in a child heap (win7)
        for h in finder.get_heap_mappings():
            # FIXME : use a get_children or something
            # winHeapwalker.get_heap_children_mmaps
            if hasattr(h, '_children'):
                if mmap in h._children:
                    found = True
                    mmap = h
                    break
        if not found:
            raise ValueError("Address is not in heap: 0x%x", address)
    _context = memory_handler.get_reverse_context()
    heap_context = _context.get_context_for_heap(mmap)
    return heap_context
