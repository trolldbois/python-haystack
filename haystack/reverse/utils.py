#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module holds some basic utils function.
"""

import itertools
import logging
import numpy
import os
import struct
import sys

from haystack.reverse import config
import haystack.reverse.enumerators
import haystack.reverse.matchers

log = logging.getLogger('utils')


def int_array_cache(filename):
    if os.access(filename, os.F_OK):
        f = file(filename, 'r')
        return numpy.load(f)
    #print 'int_array_cache'
    #import code
    #code.interact(local=locals())
    return None


def int_array_save(filename, lst):
    my_array = numpy.asarray(lst)
    numpy.save(file(filename, 'w'), my_array)
    return my_array


def closestFloorValueNumpy(val, lst):
    ''' return the closest previous value to where val should be in lst (or val)
     please use numpy.array for lst
     PERF ANOUNCEMENT - AFTER TESTING
     you are better using numpy.array, 15x for [] for type(lst) than array.array (x22)
     array.array is bad algo perf....
    '''
    # Find indices where elements should be inserted to maintain order.
    if isinstance(lst, list):  # TODO delete
        log.warning('misuse of closestFloorValue')
        #import pdb
        #pdb.set_trace()
        try:
            # be positive, its a small hit compared to searchsorted on
            # non-numpy array
            return lst.index(val)
        except ValueError as e:
            pass
        return closestFloorValueOld(val, lst)
    indicetab = numpy.searchsorted(lst, [val])
    ind = int(indicetab[0])
    if ind < len(lst):
        if long(lst[ind]) == val:
            return long(lst[ind]), ind
    if ind == 0:
        raise ValueError('Value %0x is under minimum' % (val))
    i = ind - 1
    return long(lst[i]), i


def closestFloorValueOld(val, lst):
    ''' return the closest previous value to val in lst. O(4) than numpy with numpy.array '''
    if val in lst:
        return val, lst.index(val)
    prev = lst[0]
    for i in xrange(1, len(lst) - 1):
        if lst[i] > val:
            return prev, i - 1
        prev = lst[i]
    return lst[-1], len(lst) - 1

closestFloorValue = closestFloorValueNumpy


def dequeue(addrs, start, end):
    '''
    dequeue address and return vaddr in interval ( Config.WORDSIZE ) from a list of vaddr
    dequeue addrs from 0 to start.
      dequeue all value between start and end in retval2
    return remaining after end, retval2
    '''
    ret = []
    while len(addrs) > 0 and addrs[0] < start:
        addrs.pop(0)
    # FIXME Config.WORDSIZE
    WORDSIZE = 4
    while len(addrs) > 0 and addrs[0] >= start and addrs[0] <= end - WORDSIZE:
        ret.append(addrs.pop(0))
    return addrs, ret


def _get_cache_heap_pointers(ctx, enumerator):
    """
    Cache or return Heap pointers values in enumerator .
    :param dumpfilename:
    :param heap_addr: the heap address for the cache filename
    :return:
    """
    heap_addrs_fname = ctx.get_filename_cache_pointers_addresses()
    heap_values_fname = ctx.get_filename_cache_pointers_values()
    heap_addrs = int_array_cache(heap_addrs_fname)
    heap_values = int_array_cache(heap_values_fname)
    if heap_addrs is None or heap_values is None:
        log.info('[+] Making new cache - heap pointers')
        heap_enum = enumerator.search()
        if len(heap_enum) > 0:
            heap_addrs, heap_values = zip(*heap_enum)  # WTF
        else:
            heap_addrs, heap_values = (), ()
        log.info('\t[-] got %d pointers ' % (len(heap_enum)))
        # merge
        int_array_save(heap_addrs_fname, heap_addrs)
        int_array_save(heap_values_fname, heap_values)
    else:
        log.info('[+] Loading from cache %d pointers %d unique', len(heap_values), len(set(heap_values)))
    return heap_addrs, heap_values

def cache_get_user_allocations(ctx, heap_walker):
    """
    cache the user allocations, which are the allocated chunks
        records addrs and sizes.

    :param dumpfilename:
    :param memory_handler:
    :param heapwalker:
    :return:
    """
    f_addrs = ctx.get_filename_cache_allocations_addresses()
    f_sizes = ctx.get_filename_cache_allocations_sizes()
    log.debug('reading from %s' % f_addrs)
    addrs = int_array_cache(f_addrs)
    sizes = int_array_cache(f_sizes)
    if addrs is None or sizes is None:
        log.info('[+] Making new cache - getting allocated chunks from heap ')
        # TODO : HeapWalker + order addresses ASC ...
        # allocations = sorted(heapwalker.get_user_allocations(_memory_handler, heap))
        # TODO 2 , allocations should be triaged by mmapping ( heap.start ) before write2disk.
        # Or the heap.start should be removed from the cache name.. it has no impact.
        # heapwalker.cache_get_user_allocations should parse ALL mmappings to get all user allocations.
        # But in that case, there will/could be a problem when using utils.closestFloorValue...
        # in case of a pointer ( bad allocation ) out of a mmapping space.
        # But that is not possible, because we are reporting factual reference to existing address space.
        # OK. heap.start should be deleted from the cache name.
        allocations = heap_walker.get_user_allocations()
        if len(allocations) == 0:
            return [],[]
        addrs, sizes = zip(*allocations)
        addrs = int_array_save(f_addrs, addrs)
        sizes = int_array_save(f_sizes, sizes)
    else:
        log.info('[+] Loading from cache')
    log.info('\t[-] we have %d allocated chunks', len(addrs))
    return addrs, sizes


'''
  a shareBytes array of bytes. no allocation buffer should be made, only indexes.
'''


class SharedBytes():

    def __init__(self, src):
        self.src = src
        self.start = 0
        self.end = len(src)
        return

    def __makeMe(self, start, end):
        if end < 0:
            raise ValueError
        if start < 0:
            raise ValueError
        sb = SharedBytes(self.src)
        sb.start = start
        sb.end = end
        return sb

    def unpack(self, typ, bytes):
        return struct.unpack(typ, str(bytes))

    def pack(self, typ, *val):
        return struct.pack(typ, *val)

    def __getslice__(self, start, end):
        if start < 0:  # reverse
            start = self.end + start
        elif start == sys.maxsize:
            start = self.start
        if end < 0:  # reverse
            end = self.end + end
        elif end == sys.maxsize:
            end = self.end
        return self.__makeMe(start, end)

    def __len__(self):
        return self.end - self.start

    def __getitem__(self, i):
        if isinstance(i, slice):
            return self.__getslice__(i)
        if i < 0:  # reverse
            i = self.end + i
        return self.src[self.start + i]

    def __getattribute__(self, *args):
        log.debug('__getattribute__ %d %s' % (id(self), args))
        if len(args) == 1 and args[0] == 'src':
            return getattr(self, 'src')
        return self.src[self.start:self.end]  # .__getattribute__(*args)

    def __getattr__(self, *args):
        log.debug('__getattr__ %d %s' % (id(self), args))
        return getattr(self.src[self.start:self.end], *args)

    def __setstate__(self, d):
        self.__dict__ = d.copy()

    def __getstate__(self):
        return self.__dict__.copy()

    def __str__(self):
        return self.src[self.start:self.end]

    def __repr__(self):
        return repr(self.src[self.start:self.end])

    def __iter__(self):
        return iter(self.src[self.start:self.end])


def nextStructure(context, struct):
    ind = numpy.where(context._pointers_values == struct.vaddr)[0][0]
    val = context._structures_addresses[ind + 1]
    if val not in context.structures:
        return None
    if struct.vaddr + len(struct) != val:
        print '*** WARNING nextStruct is not concurrent to struct'
    return context.getStructureForOffset[val]


def printNext(ctx, s):
    s2 = nextStructure(ctx, s)
    s2.decodeFields()
    print s2.toString()
    return s2


def flatten(listOfLists):
    return itertools.chain.from_iterable(listOfLists)
