#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import numpy
import os
import pickle
import shelve
import struct
import sys
import time

#from haystack.config import ConfigClass as Config
from haystack import dump_loader
from haystack import argparse_utils
from haystack.structures import libc

import structure
import fieldtypes
import utils

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"


log = logging.getLogger('reversers')


'''
Inherits this class when you are delivering a controller that target structure-based elements and :
  * check consistency between structures,
  * aggregate structures based on a heuristic,
'''


class StructureOrientedReverser():

    '''
      Apply heuristics on context.heap
    '''

    def __init__(self):
        self.cacheFilenames = []
        # self.cacheDict

    ''' Improve the reversing process
  '''

    def reverse(self, ctx, cacheEnabled=True):
        skip = False
        if cacheEnabled:
            ctx, skip = self._getCache(ctx)
        try:
            if skip:
                log.info('[+] skipping %s - cached results' % (str(self)))
            else:
                # call the heuristic
                self._reverse(ctx)
        except EOFError as e:  # error while unpickling
            log.error(
                'incomplete unpickling : %s - You should probably reset context.parsed' %
                (e))
            ###context.parsed = set()
            ex = sys.exc_info()
            raise ex[1], None, ex[2]
        finally:
            if cacheEnabled:
                self._putCache(ctx)
        return ctx

    ''' Subclass implementation of the reversing process '''

    def _reverse(self, ctx, addrs=None):
        raise NotImplementedError

    def _getCache(self, ctx):
        ''' define cache read on your input/output data '''
        # you should check timestamp against cache
        if str(self) in ctx.parsed:
            return ctx, True
        return ctx, False

    def _putCache(self, ctx):
        ''' define cache write on your output data '''
        t0 = time.time()
        log.info('\t[-] please wait while I am saving the context')
        # save context with cache
        ctx.save()
        return

    def _saveStructures(self, ctx):
        tl = time.time()
        if ctx._structures is None:
            log.debug('No loading has been done, not saving anything')
            return
        # dump all structures
        for i, s in enumerate(ctx._structures.values()):
            try:
                s.saveme()
            except KeyboardInterrupt as e:
                os.remove(s.fname)
                raise e
            if time.time() - tl > 30:  # i>0 and i%10000 == 0:
                t0 = time.time()
                log.info('\t\t - %2.2f secondes to go ' %
                         ((len(ctx._structures) - i) * ((tl - t0) / i)))
                tl = t0
        tf = time.time()
        log.info('\t[.] saved in %2.2f secs' % (tf - tl))
        return

    def __str__(self):
        return '<%s>' % (self.__class__.__name__)


class GenericHeapAllocationReverser(StructureOrientedReverser):

    ''' use heapwalker to get user allocations into structures.  '''

    def _reverse(self, context):
        log.info('[+] Reversing user allocations ')
        t0 = time.time()
        tl = t0
        loaded = 0
        prevLoaded = 0
        unused = 0
        # FIXME why is that a LIST ?????
        doneStructs = context._structures.keys()
        #
        todo = sorted(set(context._user_alloc_addresses) - set(doneStructs))
        fromcache = len(context._user_alloc_addresses) - len(todo)
        ##offsets = list(context._pointers_offsets)
        # build structs from pointers boundaries. and creates pointer fields if
        # possible.
        log.info(
            '[+] Adding new raw structures from getUserAllocations cached contents - %d todo' %
            (len(todo)))
        for i, (ptr_value, size) in enumerate(
                zip(map(long, context._user_alloc_addresses), map(long, context._user_alloc_sizes))):
            # TODO if len(_structure.keys()) +/- 30% de _malloc, do malloc_addr - keys() ,
            # and use fsking utils.dequeue()
            if ptr_value in doneStructs:  # FIXME TODO THAT IS SUCKY SUCKY
                sys.stdout.write('.')
                sys.stdout.flush()
                continue
            loaded += 1
            mystruct = structure.makeStructure(context, ptr_value, size)
            context._structures[ptr_value] = mystruct
            # add pointerFields
            ##offsets, my_pointers_addrs = utils.dequeue(offsets, ptr_value, ptr_value+size)
            ##log.debug('Adding %d pointer fields field on struct of size %d'%( len(my_pointers_addrs), size) )
            # optimise insertion
            # if len(my_pointers_addrs) > 0:
            ##  mystruct.addFields(my_pointers_addrs, fieldtypes.FieldType.POINTER, config.get_word_size(), False)
            # cache to disk
            mystruct.saveme()
            # next
            if time.time() - tl > 10:  # i>0 and i%10000 == 0:
                tl = time.time()
                # DEBUG...
                rate = (
                    (tl - t0) / (loaded)) if loaded else ((tl - t0) / (loaded + fromcache))
                log.info(
                    '%2.2f secondes to go (b:%d/c:%d)' %
                    ((len(todo) - i) * rate, loaded, fromcache))
        log.info(
            '[+] Extracted %d structures in %2.0f (b:%d/c:%d/u:%d)' %
            (loaded +
             fromcache,
             time.time() -
             t0,
             loaded,
             fromcache,
             unused))

        context.parsed.add(str(self))
        return


'''
  Looks at pointers values to build basic structures boundaries.

  @obselete PointerFieldsAnalyser is now doing that on the go...
'''


class PointerReverser(StructureOrientedReverser):

    '''
    slice the mapping in several structures delimited per pointer-boundaries
    '''

    def _reverse(self, context):
        log.info('[+] Reversing pointers in %s' % (context.heap))

        # make structure lengths from interval between pointers
        lengths = self.makeLengths(context.heap, context._structures_addresses)

        # we really should be lazyloading structs..
        t0 = time.time()
        tl = t0
        loaded = 0
        todo = sorted(set(context._structures_addresses) -
                      set(context._structures.keys()))
        fromcache = len(context._structures_addresses) - len(todo)
        # build structs from pointers boundaries. and creates pointer fields if
        # possible.
        log.info('[+] Adding new raw structures from pointers boundaries')
        offsets = list(context._pointers_offsets)
        for i, ptr_value in enumerate(context._structures_addresses):
            # toh stoupid
            if ptr_value in todo:
                loaded += 1
                size = lengths[i]
                # get offset of pointer fields
                offsets, my_pointers_addrs = utils.dequeue(
                    offsets, ptr_value, ptr_value + size)
                # save the ref/struct type
                mystruct = structure.makeStructure(context, ptr_value, size)
                context._structures[ptr_value] = mystruct
                # mystruct.save()
                # get pointers addrs in start -> start+size
                log.debug(
                    'Adding %d pointer fields field ' %
                    (len(my_pointers_addrs)))
                for p_addr in my_pointers_addrs:
                    f = mystruct.addField(
                        p_addr,
                        fieldtypes.FieldType.POINTER,
                        context.config.get_word_size(),
                        False)
                    #log.debug('Add field at %lx offset:%d'%( p_addr,p_addr-ptr_value))

            if time.time() - tl > 10:  # i>0 and i%10000 == 0:
                tl = time.time()
                # DEBUG...
                rate = (
                    (tl - t0) / (loaded)) if loaded else ((tl - t0) / (loaded + fromcache))
                log.info(
                    '%2.2f secondes to go (b:%d/c:%d)' %
                    ((len(todo) - i) * rate, loaded, fromcache))
        log.info(
            '[+] Extracted %d structures in %2.0f (b:%d/c:%d)' %
            (loaded + fromcache, time.time() - t0, loaded, fromcache))

        context.parsed.add(str(self))
        return

    def makeLengths(self, heap, aligned):
        lengths = [(aligned[i + 1] - aligned[i])
                   for i in range(len(aligned) - 1)]
        lengths.append(heap.end - aligned[-1])  # add tail
        return lengths

'''
  Decode each structure by asserting simple basic types from the byte content.
'''


class FieldReverser(StructureOrientedReverser):

    def _reverse(self, context):

        log.info('[+] FieldReverser: decoding fields')
        t0 = time.time()
        tl = t0
        decoded = 0
        fromcache = 0
        # writing to file
        fout = file(
            context.config.getCacheFilename(
                context.config.CACHE_GENERATED_PY_HEADERS_VALUES,
                context.dumpname),
            'w')
        towrite = []
        from haystack.reverse.heuristics.dsa import DSASimple
        dsa = DSASimple(context.config)
        # for ptr_value,anon in context.structures.items():
        for ptr_value in context.listStructuresAddresses():  # lets try reverse
            anon = context.getStructureForAddr(ptr_value)
            # TODO this is a performance hit, unproxying...
            if anon.is_resolved():
                fromcache += 1
            else:
                decoded += 1
                dsa.analyze_fields(anon)
                anon.saveme()
            # output headers
            towrite.append(anon.toString())
            if time.time() - tl > 30:  # i>0 and i%10000 == 0:
                tl = time.time()
                rate = ((tl - t0) / (decoded + fromcache)
                        ) if decoded else ((tl - t0) / (fromcache))
                log.info('%2.2f secondes to go (d:%d,c:%d)' % (
                    (context.structuresCount() - (fromcache + decoded)) * rate, decoded, fromcache))
                fout.write('\n'.join(towrite))
                towrite = []

        log.info(
            '[+] FieldReverser: finished %d structures in %2.0f (d:%d,c:%d)' %
            (fromcache + decoded, time.time() - t0, decoded, fromcache))
        context.parsed.add(str(self))
        return

'''
  Identify pointer fields and their target structure.
'''


class PointerFieldReverser(StructureOrientedReverser):

    def _reverse(self, context):
        log.info('[+] PointerFieldReverser: resolving pointers')
        t0 = time.time()
        tl = t0
        decoded = 0
        fromcache = 0
        from haystack.reverse.heuristics.dsa import EnrichedPointerFields
        pfa = EnrichedPointerFields(context.config)
        for ptr_value in context.listStructuresAddresses():  # lets try reverse
            anon = context.getStructureForAddr(ptr_value)
            if anon.is_resolvedPointers():
                fromcache += 1
            else:
                decoded += 1
                # if not hasattr(anon, 'mappings'):
                #  log.error('damned, no mappings in %x'%(ptr_value))
                #  anon.mappings = context.mappings
                pfa.analyze_fields(anon)
                anon.saveme()
            if time.time() - tl > 30:
                tl = time.time()
                rate = ((tl - t0) / (1 + decoded + fromcache)
                        ) if decoded else ((tl - t0) / (1 + fromcache))
                log.info('%2.2f secondes to go (d:%d,c:%d)' % (
                    (context.structuresCount() - (fromcache + decoded)) * rate, decoded, fromcache))
        log.info(
            '[+] PointerFieldReverser: finished %d structures in %2.0f (d:%d,c:%d)' %
            (fromcache + decoded, time.time() - t0, decoded, fromcache))
        context.parsed.add(str(self))
        return

'''
  Identify double Linked list. ( list, vector, ... )
'''


class DoubleLinkedListReverser(StructureOrientedReverser):

    def _reverse(self, context):
        log.info('[+] DoubleLinkedListReverser: resolving first two pointers')
        t0 = time.time()
        tl = t0
        done = 0
        found = 0
        members = set()
        lists = []
        for ptr_value in context.listStructuresAddresses():
            '''for i in range(1, len(context.pointers_offsets)): # find two consecutive ptr
            if context.pointers_offsets[i-1]+context.config.get_word_size() != context.pointers_offsets[i]:
              done+=1
              continue
            ptr_value = context._pointers_values[i-1]
            if ptr_value not in context.structures_addresses:
              done+=1
              continue # if not head of structure, not a classic DoubleLinkedList ( TODO, think kernel ctypes + offset)
            '''
            #anon = context.structures[ptr_value]
            if ptr_value in members:
                continue  # already checked
            if (self.isLinkedListMember(context, ptr_value)):
                head, _members = self.iterateList(context, ptr_value)
                if _members is not None:
                    members.update(_members)
                    done += len(_members) - 1
                    lists.append((head, _members))  # save list chain
                    # set names
                    context.getStructureForAddr(head).setName('list_head')
                    [context.getStructureForAddr(m).setName(
                        'list_%x_%d' % (head, i)) for i, m in enumerate(_members)]
                    # TODO get substructures ( P4P4xx ) signature and
                    # a) extract substructures
                    # b) group by signature
                    found += 1
            done += 1
            if time.time() - tl > 30:
                tl = time.time()
                rate = ((tl - t0) / (1 + done))
                #log.info('%2.2f secondes to go (d:%d,f:%d)'%( (len(context._structures)-done)*rate, done, found))
                log.info(
                    '%2.2f secondes to go (d:%d,f:%d)' %
                    ((len(
                        context._pointers_offsets) -
                        done) *
                        rate,
                        done,
                        found))
        log.info(
            '[+] DoubleLinkedListReverser: finished %d structures in %2.0f (f:%d)' %
            (done, time.time() - t0, found))
        context.parsed.add(str(self))
        #
        #context.lists = lists
        return

    def twoWords(self, ctx, st_addr, offset=0):
        """we want to read both pointers"""
        # return
        # ctx.heap.getByteBuffer()[st_addr-ctx.heap.start+offset:st_addr-ctx.heap.start+offset+2*context.config.get_word_size()]
        m = ctx.mappings.get_mapping_for_address(st_addr + offset)
        return m.readBytes(st_addr + offset, 2 * ctx.config.get_word_size())

    def unpack(self, context, ptr_value):
        """we want to read both pointers"""
        fmt = context.config.get_word_type_char()*2
        # FIXME check and delete
        #if context.config.get_word_size() == 8:
        #    return struct.unpack('QQ', self.twoWords(context, ptr_value))
        #else:
        #    return struct.unpack('LL', self.twoWords(context, ptr_value))
        return struct.unpack(fmt, self.twoWords(context, ptr_value))

    def isLinkedListMember(self, context, ptr_value):
        f1, f2 = self.unpack(context, ptr_value)
        if (f1 == ptr_value) or (f2 == ptr_value):
            # this are self pointers. ?
            return False
        # get next and prev
        if (f1 in context.heap) and (f2 in context.heap):
            st1_f1, st1_f2 = self.unpack(context, f1)
            st2_f1, st2_f2 = self.unpack(context, f2)
            # check if the three pointer work
            if ((ptr_value == st1_f2 == st2_f1) or
                    (ptr_value == st2_f2 == st1_f1)):
                #log.debug('%x is part of a double linked-list'%(ptr_value))
                if (f1 in context._structures_addresses) and (
                        f2 in context._structures_addresses):
                    return True
                else:
                    #log.debug('FP Bad candidate not head of struct: %x '%(ptr_value))
                    return False
        return False

    def iterateList(self, context, head_addr):
        members = []
        members.append(head_addr)
        f1, f2 = self.unpack(context, head_addr)
        if (f1 == head_addr):
            log.debug('f1 is head_addr too')
            return None, None
        if (f2 == head_addr):
            log.debug('f2 is head_addr too')
            context.getStructureForAddr(head_addr).setName('struct')
            log.debug(
                '%s' %
                (context.getStructureForAddr(head_addr).toString()))

        current = head_addr
        while (f1 in context._structures_addresses):
            if f1 in members:
                log.debug(
                    'loop to head - returning %d members from head.addr %x f1:%x' %
                    (len(members) - 1, head_addr, f1))
                return self.findHead(context, members)
            first_f1, first_f2 = self.unpack(context, f1)
            if (current == first_f2):
                members.append(f1)
                current = f1
                f1 = first_f1
            else:
                log.warning(
                    '(st:%x f1:%x) f2:%x is not current.addr:%x' %
                    (current, first_f1, first_f2, current))
                return None, None

        # if you leave the while, you are out of the heap address space. That
        # is probably not a linked list...
        return None, None

    def findHead(self, ctx, members):
        sizes = sorted([(ctx.getStructureSizeForAddr(m), m) for m in members])
        if sizes[0] < 3 * ctx.config.get_word_size():
            log.error('a double linked list element must be 3 WORD at least')
            raise ValueError(
                'a double linked list element must be 3 WORD at least')
        numWordSized = [s for s, addr in sizes].count(3 * ctx.config.get_word_size())
        if numWordSized == 1:
            head = sizes.pop(0)[1]
        else:  # if numWordSized > 1:
            # find one element with 0, and take that for granted...
            head = None
            for s, addr in sizes:
                if s == 3 * ctx.config.get_word_size():
                    # read ->next ptr and first field of struct || null
                    f2, field0 = self.unpack(ctx, addr + ctx.config.get_word_size())
                    if field0 == 0:  # this could be HEAD. or a 0 value.
                        head = addr
                        log.debug(
                            'We had to guess the HEAD for this linked list %x' %
                            (addr))
                        break
            if head is None:
                head = sizes[0][1]
                #raise TypeError('No NULL pointer/HEAD in the double linked list')
                log.warning(
                    'No NULL pointer/HEAD in the double linked list - head is now %x' %
                    (head))
        return (head, [m for (s, m) in sizes])

'''
  use the pointer relation between structure to map a graph.
'''


class PointerGraphReverser(StructureOrientedReverser):

    def _reverse(self, context):
        import networkx
        #import code
        # code.interact(local=locals())
        graph = networkx.DiGraph()
        # we only need the addresses...
        graph.add_nodes_from(
            ['%x' % k for k in context.listStructuresAddresses()])
        log.info('[+] Graph - added %d nodes' % (graph.number_of_nodes()))
        t0 = time.time()
        tl = t0
        for i, ptr_value in enumerate(context.listStructuresAddresses()):
            struct = context.getStructureForAddr(ptr_value)
            # targets = set(( '%x'%ptr_value, '%x'%child.target_struct_addr )
            # for child in struct.getPointerFields()) #target_struct_addr
            targets = set(
                ('%x' %
                 ptr_value,
                 '%x' %
                 child._child_addr) for child in struct.getPointerFields())  # target_struct_addr
            # DEBUG
            if len(struct.getPointerFields()) > 0:
                if len(targets) == 0:
                    raise ValueError
            # DEBUG
            graph.add_edges_from(targets)
            if time.time() - tl > 30:
                tl = time.time()
                # if decoded else ((tl-t0)/(fromcache))
                rate = ((tl - t0) / (i))
                log.info('%2.2f secondes to go (g:%d)' % (
                    (len(graph) - (i)) * rate, i))
        log.info('[+] Graph - added %d edges' % (graph.number_of_edges()))
        networkx.readwrite.gexf.write_gexf(
            graph,
            context.config.getCacheFilename(
                context.config.CACHE_GRAPH,
                context.dumpname))
        context.parsed.add(str(self))
        return


def refreshOne(context, ptr_value):
    aligned = context.structures_addresses

    lengths = [(aligned[i + 1] - aligned[i]) for i in range(len(aligned) - 1)]
    lengths.append(context.heap.end - aligned[-1])  # add tail
    size = lengths[aligned.index(ptr_value)]

    offsets = list(context.pointers_offsets)
    offsets, my_pointers_addrs = utils.dequeue(
        offsets, ptr_value, ptr_value + size)
    # save the ref/struct type
    mystruct = structure.makeStructure(context, ptr_value, size)
    context.structures[ptr_value] = mystruct
    for p_addr in my_pointers_addrs:
        f = mystruct.addField(
            p_addr,
            fieldtypes.FieldType.POINTER,
            context.config.get_word_size(),
            False)
    # resolvePointers
    mystruct.resolvePointers()
    # resolvePointers
    return mystruct


def save_headers(context, addrs=None):
    ''' structs_addrs is sorted '''
    log.info('[+] saving headers')
    fout = file(
        context.config.getCacheFilename(
            context.config.CACHE_GENERATED_PY_HEADERS_VALUES,
            context.dumpname),
        'w')
    towrite = []
    if addrs is None:
        addrs = iter(context.listStructuresAddresses())

    for vaddr in addrs:
        #anon = context._get_structures()[vaddr]
        anon = context.getStructureForAddr(vaddr)
        towrite.append(anon.toString())
        if len(towrite) >= 10000:
            try:
                fout.write('\n'.join(towrite))
            except UnicodeDecodeError as e:
                print 'ERROR on ', anon
            towrite = []
            fout.flush()
    fout.write('\n'.join(towrite))
    fout.close()
    return


def reverseInstances(dumpname):
    from haystack.reverse import context
    log.debug('[+] Loading the memory dump ')
    ctx = context.get_context(dumpname)
    try:
        if not os.access(ctx.config.getStructsCacheDir(ctx.dumpname), os.F_OK):
            os.mkdir(ctx.config.getStructsCacheDir(ctx.dumpname))

        # we use common allocators to find structures.
        #log.debug('Reversing malloc')
        #mallocRev = MallocReverser()
        #ctx = mallocRev.reverse(ctx)
        # mallocRev.check_inuse(ctx)

        # try to find some logical constructs.
        log.debug('Reversing DoubleLinkedListReverser')
        doublelink = DoubleLinkedListReverser()
        ctx = doublelink.reverse(ctx)

        # decode bytes contents to find basic types.
        log.debug('Reversing Fields')
        fr = FieldReverser()
        ctx = fr.reverse(ctx)

        # identify pointer relation between structures
        log.debug('Reversing PointerFields')
        pfr = PointerFieldReverser()
        ctx = pfr.reverse(ctx)

        # graph pointer relations between structures
        log.debug('Reversing PointerGraph')
        ptrgraph = PointerGraphReverser()
        ctx = ptrgraph.reverse(ctx)
        ptrgraph._saveStructures(ctx)

        # save to file
        save_headers(ctx)
        # fr._saveStructures(ctx)
        ##libRev = KnowStructReverser('libQt')
        ##ctx = libRev.reverse(ctx)
        # we have more enriched context

        # etc
    except KeyboardInterrupt as e:
        # except IOError,e:
        log.warning(e)
        log.info('[+] %d structs extracted' % (context.structuresCount()))
        raise e
        pass
    pass

if __name__ == '__main__':
    pass
