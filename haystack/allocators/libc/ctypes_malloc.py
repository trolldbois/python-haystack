#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

from haystack import listmodel

log = logging.getLogger('ctypes_malloc')


# SIZE_SZ = Config.WORDSIZE
# MIN_CHUNK_SIZE        = 4 * SIZE_SZ
# MALLOC_ALIGNMENT    = 2 * SIZE_SZ
# MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
# MINSIZE                     = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

PREV_INUSE = 1
IS_MMAPPED = 2
NON_MAIN_ARENA = 4
SIZE_BITS = (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)




def is_malloc_heap(memory_handler, mapping):
    """test if a mapping is a malloc generated heap"""
    target_platform = memory_handler.get_target_platform()
    validator = LibcHeapValidator(memory_handler, None, sys.modules[__name__])
    try:
        # i'm lazy. Heap validation could be 10 chunks deep.
        # but we validate _is_heap by looking at the mapping size
        sizes = [
            size for (
                addr,
                size) in validator.iter_user_allocations(
                mapping)]
        size = sum(sizes)
    except ValueError as e:
        log.debug(e)
        return False
    except NotImplementedError as e:
        # file absent
        log.debug(e)
        return False
    # FIXME: is malloc word size dependent
    if size != (len(mapping) - target_platform.get_word_size() * len(sizes)):
        log.debug(
            'expected %d/%d bytes, got %d' %
            (len(mapping),
             len(mapping) -
                2 *
                target_platform.get_word_size() *
                len(sizes),
                size))
        return False
    return True


class LibcHeapValidator(listmodel.ListModel):
    """
    this listmodel Validator will register know important list fields
    in the win7 HEAP,
    [ FIXME TODO and apply constraints ? ]
    and be used to validate the loading of these allocators.
    This class contains all helper functions used to parse the win7heap allocators.

        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()
        self._ctypes = self._target.get_target_ctypes()
        self._utils = self._target.get_target_ctypes_utils()
        self._constraints = my_constraints

    """

    def __init__(self, memory_handler, my_constraints, libc_heap_module):
        super(LibcHeapValidator, self).__init__(memory_handler, my_constraints)
        self.libc_heap_module = libc_heap_module
        # LIST_ENTRY
        # self.register_double_linked_list_record_type(self.win7heap.LIST_ENTRY, 'Flink', 'Blink')
        pass

    def get_mem_addr(self, orig_addr):
        return orig_addr + 2 * self._utils.get_word_size()

    def get_mem_size(self, record):
        return self.real_size(record) - self._utils.get_word_size()

    def real_size(self, record):
        return (record.size & ~SIZE_BITS)

    def next_addr(self, record, orig_addr):
        return orig_addr + self.real_size(record)

    def prev_addr(self, record, orig_addr):
        return orig_addr - record.prev_size

    def check_prev_inuse(self, record):
        return record.size & PREV_INUSE

    def check_inuse(self, record, orig_addr):
        """extract p's inuse bit
        doesnt not work on the top one
        """
        next_addr = self.next_addr(record, orig_addr) + self._utils.get_word_size()
        mmap = self._memory_handler.is_valid_address_value(next_addr)
        if not mmap:
            return 0
            # raise ValueError()
        next_size = mmap.read_word(next_addr)
        return next_size & PREV_INUSE

    def is_valid(self, record):
        """

        :param record:
        :return:
        """
        # get the real data headers. size of fields of based on struct definition
        #    (self.prev_size,    self.size) = struct.unpack_from("<II", mem, 0x0)
        real_size = self.real_size(record)
        if real_size == 0:
            log.debug('real_size is 0')
            return False
        if True:
            log.debug('record.prev_size %d' % record.prev_size)
            log.debug('record.size %d' % record.size)
            log.debug('real_size %d' % real_size)

        # inuse : to know if inuse, you have to look at next_chunk.size &
        # PREV_SIZE bit
        # try:
        inuse = self.check_inuse(record, record._orig_address_)
        # except Exception,e:
        #    log.error("Exception while checking inuse:"+str(e))
        #    raise e
        #    return False
        log.debug('is chunk in use ?: %s' % bool(inuse))

        if real_size % self._utils.get_word_size() != 0:
            # not a good value
            log.debug('real_size is not a WORD SIZE moduli')
            return False

        return True

    def load_members(self, record, max_depth):
        """

        :param record:
        :param max_depth:
        :return:
        """
        if max_depth <= 0:
            log.debug('Maximum depth reach. Not loading any deeper members.')
            log.debug(
                'Struct partially LOADED. %s not loaded',
                record.__class__.__name__)
            return True
        max_depth -= 1
        log.debug('%s load_members', record.__class__.__name__)
        if not self.is_valid(record):
            return False
        try:

            if self.check_prev_inuse(record):  # if in use, prev_size is not readable
                # self.prev_size = 0
                pass
            else:
                prev, prev_addr = self.get_prev_chunk(
                    record, record._orig_address_, max_depth)
                if prev_addr is not None:
                    log.debug('prevchunk: 0x%x', prev_addr)

            # update virtual fields
            if record.size != 0:
                next, next_addr = self.get_next_chunk(
                    record, record._orig_address_, max_depth)
                if next_addr is not None:
                    log.debug('nextchunk: 0x%x',next_addr)

            # if next_addr is None: #most of the time its not
            #    return True
        except ValueError as e:
            log.debug(e)
            return False
        return True

    def get_prev_chunk(self, record, orig_addr, depth):
        # do prev_chunk
        if self.check_prev_inuse(record):
            raise TypeError('Previous chunk is in use. can read its size.')
        mmap = self._memory_handler.is_valid_address_value(orig_addr)
        if not mmap:
            raise ValueError(
                'STOP: prev orig_addr invalid: 0x%x' %
                orig_addr)
        # FIXME: check if this is correct. No prev to start of maps
        if mmap.start == orig_addr:
            log.debug(
                'STOP: prev orig_addr is same as mapping.start: 0x%x',
                orig_addr)
            return None, None
        if record.prev_size > 0:
            prev_addr = orig_addr - record.prev_size
            if not self._memory_handler.is_valid_address_value(prev_addr):
                raise ValueError('STOP: prev_addr invalid: 0x%x' % prev_addr)
            # if prev_addr not in mmap:
            #    mmap = _memory_handler.is_valid_address_value(prev_addr)
            prev_chunk = mmap.read_struct(prev_addr, malloc_chunk)
            self._memory_handler.keepRef(prev_chunk, malloc_chunk, prev_addr)
            # load
            if depth > 0:
                ret = self.load_members(prev_chunk, depth)
                if not ret:
                    raise ValueError('next_chunk not loaded')
            return prev_chunk, prev_addr
        raise ValueError('STOP: prev_size <=0: 0x%x' % record.prev_size)

    def get_next_chunk(self, record, orig_addr, depth):
        # do next_chunk
        mmap = self._memory_handler.is_valid_address_value(orig_addr)
        if not mmap:
            raise ValueError(
                'STOP: next orig_addr invalid: 0x%x' %
                orig_addr)
        next_addr = orig_addr + self.real_size(record)
        log.debug(
            'next_addr: 0x%x realsize:0x%x' %
            (next_addr, self.real_size(record)))
        if next_addr == orig_addr:
            return None, None
        # check if its in _memory_handler
        if not self._memory_handler.is_valid_address_value(next_addr):
            current_heap = self._memory_handler.get_mapping_for_address(orig_addr)
            if next_addr == current_heap.end:
                log.debug('Last chunk: size: 0x%x' % (self.real_size(record)))
                return None, None
            raise ValueError('STOP: next_addr invalid: 0x%x' % next_addr)
        next_chunk = mmap.read_struct(next_addr, malloc_chunk)
        self._memory_handler.keepRef(next_chunk, malloc_chunk, next_addr)
        if depth > 0:
            ret = self.load_members(next_chunk, depth)
            if not ret:
                raise ValueError('next_chunk not loaded')
        return next_chunk, next_addr

    def iter_user_allocations(self, heap, filter_in_use=False):
        """
        Lists all (addr, size) of allocated space by malloc_chunks.
        """
        # allocations = [] # index, size
        orig_addr = heap.start

        chunk = heap.read_struct(orig_addr, malloc_chunk)
        assert hasattr(chunk, '_orig_address_')
        ret = self.load_members(chunk, 10)
        if not ret:
            raise ValueError('heap does not start with an malloc_chunk')
        addr, size = (self.get_mem_addr(orig_addr), self.get_mem_size(chunk))
        if size < 0:  # chunk.size is 0, its invalid
            raise StopIteration

        if filter_in_use:
            if self.check_inuse(chunk, orig_addr):
                yield (addr, size)
        else:
            yield (addr, size)

        while True:
            next, next_addr = self.get_next_chunk(chunk, orig_addr, 0)
            if next_addr is None:
                break
            ret = self.load_members(next, 10)
            if not ret:
                raise ValueError
            if filter_in_use:
                if self.check_inuse(next, next_addr):
                    yield (self.get_mem_addr(next_addr), self.get_mem_size(next))
            else:
                yield (self.get_mem_addr(next_addr), self.get_mem_size(next))
            # next loop
            orig_addr = next_addr
            chunk = next

        raise StopIteration

    def get_user_allocations(self, heap, filter_on_used=False):
        """
        Lists all (addr, size) of allocated space by malloc_chunks.
        """
        allocs = []  # index, size
        free = []

        orig_addr = heap.start
        chunk = heap.read_struct(orig_addr, malloc_chunk)
        ret = self.load_members(chunk, 10)
        if not ret:
            raise ValueError('heap does not start with an malloc_chunk')
        addr, size = (self.get_mem_addr(orig_addr), self.get_mem_size(chunk))
        if self.check_inuse(chunk, orig_addr):
            allocs.append((addr, size))
        else:
            free.append((addr, size))

        while True:
            next, next_addr = self.get_next_chunk(chunk, orig_addr, 0)
            if next_addr is None:
                break
            ret = self.load_members(next, 10)
            if not ret:
                raise ValueError
            if self.check_inuse(next, next_addr):
                allocs.append((self.get_mem_addr(next_addr), self.get_mem_size(next)))
            else:
                free.append((self.get_mem_addr(next_addr), self.get_mem_size(next)))
            # next loop
            orig_addr = next_addr
            chunk = next

        return allocs, free

class malloc_chunk(ctypes.Structure):

    """FAKE python representation of a struct malloc_chunk

struct malloc_chunk {

    INTERNAL_SIZE_T            prev_size;    /* Size of previous chunk (if free).    */
    INTERNAL_SIZE_T            size;             /* Size in bytes, including overhead. */

    struct malloc_chunk* fd;                 /* double links -- used only if free. */
    struct malloc_chunk* bk;

    /* Only used for large blocks: pointer to next larger size.    */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
};

0000000 0000 0000 0011 0000 beef dead 1008 0927
0000010 0000 0000 0019 0000 beef dead 1010 1010
0000020 1018 0927 1010 1010 beef dead 0fd9 0002
0000030 0000 0000 0000 0000 0000 0000 0000 0000

    """

malloc_chunk._fields_ = [
    ('prev_size', ctypes.c_ulong),  # INTERNAL_SIZE_T
    ('size', ctypes.c_ulong),  # INTERNAL_SIZE_T with some flags
    # totally virtual
]


