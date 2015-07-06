#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import sys

from haystack import model
# FIXME: ctypes = types.reload_ctyps(4,4,8) #?
import ctypes

log = logging.getLogger('ctypes_malloc')


#SIZE_SZ = Config.WORDSIZE
#MIN_CHUNK_SIZE        = 4 * SIZE_SZ
#MALLOC_ALIGNMENT    = 2 * SIZE_SZ
#MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
#MINSIZE                     = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

PREV_INUSE = 1
IS_MMAPPED = 2
NON_MAIN_ARENA = 4
SIZE_BITS = (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)


def iter_user_allocations(mappings, heap, filterInuse=False):
    """
    Lists all (addr, size) of allocated space by malloc_chunks.
    """
    # allocations = [] # index, size
    orig_addr = heap.start

    chunk = heap.read_struct(orig_addr, malloc_chunk)
    assert hasattr(chunk, '_orig_address_')
    ret = chunk.loadMembers(mappings, 10)
    if not ret:
        raise ValueError('heap does not start with an malloc_chunk')
    addr, size = (chunk.get_mem_addr(orig_addr), chunk.get_mem_size())
    if size < 0:  # chunk.size is 0, its invalid
        raise StopIteration

    if filterInuse:
        if chunk.check_inuse(mappings, orig_addr):
            yield (addr, size)
    else:
        yield (addr, size)

    while True:
        next, next_addr = chunk.getNextChunk(mappings, orig_addr, 0)
        if next_addr is None:
            break
        ret = next.loadMembers(mappings, 10)
        if not ret:
            raise ValueError
        if filterInuse:
            if next.check_inuse(mappings, next_addr):
                yield (next.get_mem_addr(next_addr), next.get_mem_size())
        else:
            yield (next.get_mem_addr(next_addr), next.get_mem_size())
        # next loop
        orig_addr = next_addr
        chunk = next

    raise StopIteration


def get_user_allocations(mappings, heap, filterOnUsed=False):
    """
    Lists all (addr, size) of allocated space by malloc_chunks.
    """
    allocs = []  # index, size
    free = []

    orig_addr = heap.start
    chunk = heap.read_struct(orig_addr, malloc_chunk)
    ret = chunk.loadMembers(mappings, 10)
    if not ret:
        raise ValueError('heap does not start with an malloc_chunk')
    addr, size = (chunk.get_mem_addr(orig_addr), chunk.get_mem_size())
    if chunk.check_inuse(mappings, orig_addr):
        allocs.append((addr, size))
    else:
        free.append((addr, size))

    while True:
        next, next_addr = chunk.getNextChunk(mappings, orig_addr, 0)
        if next_addr is None:
            break
        ret = next.loadMembers(mappings, 10)
        if not ret:
            raise ValueError
        if next.check_inuse(mappings, next_addr):
            allocs.append((next.get_mem_addr(next_addr), next.get_mem_size()))
        else:
            free.append((next.get_mem_addr(next_addr), next.get_mem_size()))
        # next loop
        orig_addr = next_addr
        chunk = next

    return allocs, free


def is_malloc_heap(mappings, mapping):
    """test if a mapping is a malloc generated heap"""
    target_platform = mappings.get_target_platform()
    try:
        # i'm lazy. Heap validation could be 10 chunks deep.
        # but we validate _is_heap by looking at the mapping size
        sizes = [
            size for (
                addr,
                size) in iter_user_allocations(
                mappings,
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


class mallocStruct(ctypes.Structure):

    """ defines classRef """
    pass


class malloc_chunk(mallocStruct):

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

    def get_mem_addr(self, orig_addr):
        return orig_addr + 2 * self._mappings.get_target_platform().get_word_size()

    def get_mem_size(self):
        return self.real_size() - self._mappings.get_target_platform().get_word_size()

    def real_size(self):
        return (self.size & ~SIZE_BITS)

    def next_addr(self, orig_addr):
        return orig_addr + self.real_size()

    def prev_addr(self, orig_addr):
        return orig_addr - self.prev_size

    def check_prev_inuse(self):
        return self.size & PREV_INUSE

    def check_inuse(self, mappings, orig_addr):
        """extract p's inuse bit
        doesnt not work on the top one
        """
        next_addr = self.next_addr(orig_addr) + self._mappings.get_target_platform().get_word_size()
        mmap = mappings.is_valid_address_value(next_addr)
        if not mmap:
            return 0
            #raise ValueError()
        next_size = mmap.read_word(next_addr)
        return next_size & PREV_INUSE

    def isValid(self, mappings):
        """

        :param mappings:
        :return:
        """
        self._mappings = mappings
        # get the real data headers. size of fields of based on struct definition
        #    (self.prev_size,    self.size) = struct.unpack_from("<II", mem, 0x0)
        real_size = self.real_size()
        #import code
        #code.interact(local=locals())
        if real_size == 0:
            log.debug('real_size is 0')
            return False
        if True:
            log.debug('self.prev_size %d' % self.prev_size)
            log.debug('self.size %d' % self.size)
            log.debug('real_size %d' % real_size)

        # inuse : to know if inuse, you have to look at next_chunk.size &
        # PREV_SIZE bit
        #try:
        inuse = self.check_inuse(mappings, self._orig_address_)
        #except Exception,e:
        #    log.error("Exception while checking inuse:"+str(e))
        #    raise e
        #    return False
        log.debug('is chunk in use ?: %s' % bool(inuse))

        if real_size % self._mappings.get_target_platform().get_word_size() != 0:
            # not a good value
            log.debug('real_size is not a WORD SIZE moduli')
            return False

        return True

    def loadMembers(self, mappings, maxDepth):
        """

        :param mappings:
        :param maxDepth:
        :return:
        """
        self._mappings = mappings
        if maxDepth <= 0:
            log.debug('Maximum depth reach. Not loading any deeper members.')
            log.debug(
                'Struct partially LOADED. %s not loaded' %
                (self.__class__.__name__))
            return True
        self.config = mappings.config
        maxDepth -= 1
        log.debug('%s loadMembers' % (self.__class__.__name__))
        if not self.isValid(mappings):
            return False
        try:

            if self.check_prev_inuse():  # if in use, prev_size is not readable
                #self.prev_size = 0
                pass
            else:
                prev, prev_addr = self.getPrevChunk(
                    mappings, self._orig_address_, maxDepth)
                if prev_addr is not None:
                    log.debug('prevchunk: 0x%x',prev_addr)

            # update virtual fields
            if self.size != 0:
                next, next_addr = self.getNextChunk(
                    mappings, self._orig_address_, maxDepth)
                if next_addr is not None:
                    log.debug('nextchunk: 0x%x',next_addr)

            # if next_addr is None: #most of the time its not
            #    return True
        except ValueError as e:
            log.debug(e)
            return False
        return True

    def getPrevChunk(self, mappings, orig_addr, depth):
        # do prev_chunk
        if self.check_prev_inuse():
            raise TypeError('Previous chunk is in use. can read its size.')
        mmap = mappings.is_valid_address_value(orig_addr)
        if not mmap:
            raise ValueError(
                'STOP: prev orig_addr invalid: 0x%x' %
                orig_addr)
        # FIXME: check if this is correct. No prev to start of maps
        if mmap.start == orig_addr:
            log.debug(
                'STOP: prev orig_addr is same as mapping.start: 0x%x' %
                orig_addr)
            return None, None
        if self.prev_size > 0:
            prev_addr = orig_addr - self.prev_size
            if not mappings.is_valid_address_value(prev_addr):
                raise ValueError('STOP: prev_addr invalid: 0x%x' % prev_addr)
            # if prev_addr not in mmap:
            #    mmap = _memory_handler.is_valid_address_value(prev_addr)
            prev_chunk = mmap.read_struct(prev_addr, malloc_chunk)
            mappings.keepRef(prev_chunk, malloc_chunk, prev_addr)
            # load
            if depth > 0:
                ret = prev_chunk.loadMembers(mappings, depth)
                if not ret:
                    raise ValueError('next_chunk not loaded')
            return prev_chunk, prev_addr
        raise ValueError('STOP: prev_size <=0: 0x%x'%self.prev_size)

    def getNextChunk(self, mappings, orig_addr, depth):
        # do next_chunk
        mmap = mappings.is_valid_address_value(orig_addr)
        if not mmap:
            raise ValueError(
                'STOP: next orig_addr invalid: 0x%x' %
                (orig_addr))
        next_addr = orig_addr + self.real_size()
        log.debug(
            'next_addr: 0x%x realsize:0x%x' %
            (next_addr, self.real_size()))
        if next_addr == orig_addr:
            return None, None
        # check if its in _memory_handler
        if not mappings.is_valid_address_value(next_addr):
            current_heap = mappings.get_mapping_for_address(orig_addr)
            if next_addr == current_heap.end:
                log.debug('Last chunk: size: 0x%x' % (self.real_size()))
                return None, None
            raise ValueError('STOP: next_addr invalid: 0x%x' % (next_addr))
        next_chunk = mmap.read_struct(next_addr, malloc_chunk)
        mappings.keepRef(next_chunk, malloc_chunk, next_addr)
        if depth > 0:
            ret = next_chunk.loadMembers(mappings, depth)
            if not ret:
                raise ValueError('next_chunk not loaded')
        return next_chunk, next_addr


# Unint is 32. always. - so not true.
UINT = ctypes.c_uint


malloc_chunk._fields_ = [
    ('prev_size', ctypes.c_ulong),  # INTERNAL_SIZE_T
    ('size', ctypes.c_ulong),  # INTERNAL_SIZE_T with some flags
    # totally virtual
]
# make subclass for empty or inuse..

# cant use 2** expectedValues, there is a mask on sizes...
malloc_chunk.expectedValues = {}


model.registerModule(sys.modules[__name__])
