# -*- coding: utf-8 -*-

import logging
import struct
import sys
import time

import os

from haystack.reverse import config
from haystack.reverse import structure
from haystack.reverse import fieldtypes
from haystack.reverse import utils
from haystack.reverse import interfaces
from haystack.reverse import pattern
from haystack.reverse.heuristics import dsa

"""
BasicCachingReverser:
    use heapwalker to organise heap user allocations chunks into raw records.

RecordReverser:
    Implement this class when you are delivering a IRecordReverser
    The reverse method will iterate on all record in a context and call reverse_record

FieldReverser:
    Decode each structure by asserting simple basic types from the byte content.

PointerFieldReverser:
    Identify pointer fields and their target structure.

DoubleLinkedListReverser:
    Identify double Linked list. ( list, vector, ... )

PointerGraphReverser:
    use the pointer relation between records to map a graph.

save_headers:
    Save the python class code definition to file.

reverse_instances:
        # we use common allocators to find structures.
        use DoubleLinkedListReverser to try to find some double linked lists records
        use FieldReverser to decode bytes contents to find basic types
        use PointerFieldReverser to identify pointer relation between structures
        use PointerGraphReverser to graph pointer relations between structures
        save guessed records' python code definition to file
"""

log = logging.getLogger('reversers')


## TODO:
# implement Anaonstructure .get_address()
# implement AnonStructure.get_reverse_level()


class BasicCachingReverser(interfaces.IContextReverser):
    """
    Uses heapwalker to get user allocations into structures in cache.
    This reverser should be use as a first step in the reverse process.
    """
    def __init__(self, _context):
        self._reverse_level = 1
        self._context = _context

    def get_reverse_level(self):
        return self._reverse_level

    def reverse(self):
        log.info('[+] Reversing user allocations into cache')
        t0 = time.time()
        tl = t0
        loaded = 0
        unused = 0
        # FIXME why is that a LIST ?????
        doneStructs = self._context._structures.keys()
        allocations = self._context.list_allocations_addresses()
        #
        todo = sorted(set(allocations) - set(doneStructs))
        fromcache = len(allocations) - len(todo)
        log.info('[+] Adding new raw structures from getUserAllocations cached contents - %d todo', len(todo))
        for i, (ptr_value, size) in enumerate(
                zip(map(long, allocations), map(long, self._context.list_allocations_sizes()))):
            if ptr_value in doneStructs:  # FIXME TODO THAT IS SUCKY SUCKY
                sys.stdout.write('.')
                sys.stdout.flush()
                continue
            loaded += 1
            if size < 0:
                log.error("Negative allocation size")
            mystruct = structure.makeStructure(self._context, ptr_value, size)
            self._context._structures[ptr_value] = mystruct
            # cache to disk
            mystruct.saveme()
            # next
            if time.time() - tl > 10:  # i>0 and i%10000 == 0:
                tl = time.time()
                # DEBUG...
                rate = ((tl - t0) / (loaded)) if loaded else ((tl - t0) / (loaded + fromcache))
                log.info('%2.2f secondes to go (b:%d/c:%d)', (len(todo) - i) * rate, loaded, fromcache)
        # finishing statements
        total = loaded + fromcache
        ts = time.time() - t0
        log.info('[+] Extracted %d structures in %2.0f (b:%d/c:%d/u:%d)', total, ts, loaded, fromcache, unused)
        return


class AbstractReverser(interfaces.IContextReverser):
    """
    Implements helper wraps
    """
    def __init__(self, _context, _reverse_level):
        self._context = _context
        self._reverse_level = _reverse_level
        # save to file
        self._fout = file(self._context.get_filename_cache_headers(), 'w')
        self._towrite = []

    def get_reverse_level(self):
        return self._reverse_level

    def reverse(self):
        """
        Go over each record and call the reversing process.
        Wraps around some time-based function to ease the wait.
        Saves the context to cache at the end.
        """
        log.info('[+] %s: START', self)
        self._t0 = time.time()
        self._tl = self._t0
        self._nb_reversed = 0
        self._nb_from_cache = 0
        # run the reverser
        self.reverse_context(self._context)
        # save the context
        self._context.save()
        # closing statements
        total = self._nb_from_cache + self._nb_reversed
        ts = time.time() - self._t0
        log.info('[+] %s: END %d records in %2.0f (d:%d,c:%d)', self, total, ts, self._nb_reversed, self._nb_from_cache)
        return

    def _callback(self):
        # every 30 secs, print a statement, save text repr to file.
        if time.time() - self._tl > 30:
            tl = time.time()
            rate = (tl - self._t0) / (1 + self._nb_reversed + self._nb_from_cache)
            _ttg = (self._context.structuresCount() - (self._nb_from_cache + self._nb_reversed)) * rate
            log.info('%2.2f secondes to go (d:%d,c:%d)', _ttg, self._nb_reversed, self._nb_from_cache)
            # write to file
            self._fout.write('\n'.join(self._towrite))
            self._towrite = []

        return

    def _append_to_write(self, _content):
        self._towrite.append(_content)

    def _write(self):
        self._fout.write('\n'.join(self._towrite))
        self._towrite = []

    def __str__(self):
        return '<%s>' % self.__class__.__name__

    def reverse_context(self, _context):
        """
        Subclass implementation of the reversing process

        Should iterate over records.
        """
        raise NotImplementedError


class DoubleLinkedListReverser(AbstractReverser):
    """
      Identify double Linked list. ( list, vector, ... )
    """
    def __init__(self, _context):
        super(DoubleLinkedListReverser, self).__init__(_context, _reverse_level=20)
        self._target = _context.memory_handler.get_target_platform()

    def reverse_context(self, _context):
        """
        for i in range(1, len(context.pointers_offsets)): # find two consecutive ptr
            if context.pointers_offsets[i-1]+context._target_platform.get_word_size() != context.pointers_offsets[i]:
              done+=1
              continue
            ptr_value = context._pointers_values[i-1]
            if ptr_value not in context.structures_addresses:
              done+=1
              continue
              # if not head of structure, not a classic DoubleLinkedList ( TODO, think kernel ctypes + offset)
        """
        if self._context != _context:
            raise ValueError("The _context should be the same as initialization time.")
        found = 0
        members = set()
        lists = []
        for ptr_value in self._context.listStructuresAddresses():
            if ptr_value in members:
                # already checked as part of a list
                self._nb_from_cache += 1
                return
            if self.is_linked_list_member(ptr_value):
                head, _members = self.iterate_list(ptr_value)
                if _members is not None:
                    members.update(_members)
                    self._nb_reversed += len(_members) - 1
                    lists.append((head, _members))  # save list chain
                    # set names
                    _context.get_structure_for_address(head).set_name('list_head')
                    [_context.get_structure_for_address(m).set_name(
                        'list_%x_%d' % (head, i)) for i, m in enumerate(_members)]
                    # TODO get substructures ( P4P4xx ) signature and
                    # a) extract substructures
                    # b) group by signature
                    found += 1
            self._nb_reversed += 1
            self._callback()
        return

    def is_linked_list_member(self, ptr_value):
        """
        Checks if this address hold a DoubleLinkedPointer record with forward and backward pointers.
        :param ptr_value:
        :return:
        """
        f1, f2 = self.get_two_pointers(ptr_value)
        if (f1 == ptr_value) or (f2 == ptr_value):
            # this are self pointers that could be a list head or end
            return False
        # get next and prev in the same HEAP
        if (f1 in self._context.heap) and (f2 in self._context.heap):
            st1_next, st1_prev = self.get_two_pointers(f1)
            st2_next, st2_prev = self.get_two_pointers(f2)
            # check if the three pointer work
            if (ptr_value == st1_prev == st2_next) or (ptr_value == st2_prev == st1_next):
                # log.debug('%x is part of a double linked-list', ptr_value)
                if self._context.is_known_address(f1) and self._context.is_known_address(f2):
                    return True
                else:
                    # log.debug('FP Bad candidate not head of struct: %x ', ptr_value)
                    # FIXME: x2LinkEntry record could be a substructure.
                    return False
        return False

    def get_two_pointers(self, st_addr, offset=0):
        """
        Read two words from an address as to get 2 pointers out.
        usually that is what a double linked list structure is.
        """
        # TODO add PEP violation fmt ignore. get_word_type_char returns a str()
        fmt = str(self._target.get_word_type_char()*2)
        m = self._context.memory_handler.get_mapping_for_address(st_addr + offset)
        _bytes = m.read_bytes(st_addr + offset, 2 * self._target.get_word_size())
        return struct.unpack(fmt, _bytes)

    def iterate_list(self, head_addr):
        """
        Iterate the list starting at head_addr.
        :param head_addr:
        :return:
        """
        # FIXME: does not go backwards. Fix with ListModel. algo.
        members = [head_addr]
        f1, f2 = self.get_two_pointers(head_addr)
        if f1 == head_addr:
            log.debug('f1 is head_addr too')
            return None, None
        if f2 == head_addr:
            log.debug('f2 is head_addr too')
            self._context.get_structure_for_address(head_addr).set_name('struct')
            log.debug('%s', self._context.get_structure_for_address(head_addr).to_string())

        current = head_addr
        while self._context.is_known_address(f1):
            if f1 in members:
                log.debug('loop to head - returning %d members from head.addr %x f1:%x', len(members) - 1, head_addr, f1)
                return self.find_list_head(members)
            first_f1, first_f2 = self.get_two_pointers(f1)
            if current == first_f2:
                members.append(f1)
                current = f1
                f1 = first_f1
            else:
                log.warning('(st:%x f1:%x) f2:%x is not current.addr:%x', current, first_f1, first_f2, current)
                return None, None

        # if you leave the while, you are out of the heap address space. That
        # is probably not a linked list...
        return None, None

    def find_list_head(self, members):
        sizes = sorted([(self._context.getStructureSizeForAddr(m), m) for m in members])
        if sizes[0] < 3 * self._target.get_word_size():
            log.error('a double linked list element must be 3 WORD at least')
            raise ValueError(
                'a double linked list element must be 3 WORD at least')
        numWordSized = [s for s, addr in sizes].count(3 * self._target.get_word_size())
        if numWordSized == 1:
            head = sizes.pop(0)[1]
        else:  # if numWordSized > 1:
            # find one element with 0, and take that for granted...
            head = None
            for s, addr in sizes:
                if s == 3 * self._target.get_word_size():
                    # read ->next ptr and first field of struct || null
                    f2, field0 = self.get_two_pointers(addr + self._target.get_word_size())
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


class RecordReverser(AbstractReverser, interfaces.IRecordReverser):
    """
    Inherits this class when you are delivering a controller that target structure-based elements.
      * Implement reverse_record(self, _record)
    """
    def __init__(self, _context, _reverse_level):
        super(RecordReverser, self).__init__(_context, _reverse_level)

    def reverse_context(self, _context):
        """
        Go over each record and call the reversing process.
        Wraps around some time-based function to ease the wait.
        Saves the context to cache at the end.
        """
        for _record in _context.listStructures():
            if _record.get_reverse_level() >= self.get_reverse_level():
                # ignore this record. its already reversed.
                self._nb_from_cache += 1
            else:
                self._nb_reversed += 1
                # call the heuristic
                self.reverse_record(_record)
            # output headers
            self._append_to_write(_record.to_string())
            self._callback()
        ##
        self._context.save()
        return

    def reverse_record(self, _record):
        """
        Subclass implementation of the reversing process

        Should set _reverse_level of _record.
        """
        raise NotImplementedError


class FieldReverser(RecordReverser):
    """
    Decode each structure by asserting simple basic types from the byte content.

    It tries the followings heuristics:
        ZeroFields
        PrintableAsciiFields
        UTF16Fields
        IntegerFields
        PointerFields

    """
    def __init__(self, _context):
        super(FieldReverser, self).__init__(_context, _reverse_level=30)
        self._dsa = dsa.DSASimple(self._context.memory_handler)

    def reverse_record(self, _record):
        # writing to file
        # for ptr_value,anon in context.structures.items():
        self._dsa.analyze_fields(_record)
        _record.set_reverse_level(self._reverse_level)
        return


class PointerFieldReverser(RecordReverser):
    """
      Identify pointer fields and their target structure.

      You should call this Reverser only when all heaps have been reverse.
      TODO: add minimum reversing level check before running
    """

    def __init__(self, _context):
        super(PointerFieldReverser, self).__init__(_context, _reverse_level=50)
        self._pfa = dsa.EnrichedPointerFields(self._context.memory_handler)

    def reverse_record(self, _record):
        # writing to file
        # for ptr_value,anon in context.structures.items():
        self._pfa.analyze_fields(_record)
        _record.set_reverse_level(self._reverse_level)
        return


class PointerGraphReverser(RecordReverser):
    """
      use the pointer relation between structure to map a graph.
    """
    def __init__(self, _context):
        super(PointerGraphReverser, self).__init__(_context, _reverse_level=60)

    def reverse_record(self, context):
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
            struct = context.get_structure_for_address(ptr_value)
            # targets = set(( '%x'%ptr_value, '%x'%child.target_struct_addr )
            # for child in struct.getPointerFields()) #target_struct_addr
            # target_struct_addr
            targets = set(('%x' % ptr_value, '%x' % child._child_addr) for child in struct.get_pointer_fields())
            # DEBUG
            if len(struct.get_pointer_fields()) > 0:
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
        networkx.readwrite.gexf.write_gexf(graph, context.get_filename_cache_graph())
        context.parsed.add(str(self))
        return


class ArrayFieldsReverser(RecordReverser):
    """
    Aggregate fields of similar type into arrays in the record.
    """
    def __init__(self, _context):
        super(ArrayFieldsReverser, self).__init__(_context, _reverse_level=100)

    def reverse_record(self, _record):
        """
            Aggregate fields of similar type into arrays in the record.
        """
        # if not self.resolvedPointers:
        #  raise ValueError('I should be resolved')
        _record._dirty = True

        _record._fields.sort()
        myfields = []

        signature = _record.getSignature()
        pencoder = pattern.PatternEncoder(signature, minGroupSize=3)
        patterns = pencoder.makePattern()

        #txt = self.getSignature(text=True)
        #log.warning('signature of len():%d, %s'%(len(txt),txt))
        #p = pattern.findPatternText(txt, 2, 3)
        # log.debug(p)

        #log.debug('aggregateFields came up with pattern %s'%(patterns))

        # pattern is made on FieldType,
        # so we need to dequeue self.fields at the same time to enqueue in
        # myfields
        for nb, fieldTypesAndSizes in patterns:
            # print 'fieldTypesAndSizes:',fieldTypesAndSizes
            if nb == 1:
                fieldType = fieldTypesAndSizes[0]  # its a tuple
                field = _record._fields.pop(0)
                myfields.append(field)  # single el
                #log.debug('simple field:%s '%(field) )
            # array of subtructure DEBUG XXX TODO
            elif len(fieldTypesAndSizes) > 1:
                log.debug('substructure with sig %s' % (fieldTypesAndSizes))
                myelements = []
                for i in range(nb):
                    fields = [ _record._fields.pop(0) for i in range(len(fieldTypesAndSizes))]  # nb-1 left
                    #otherFields = [ self.fields.pop(0) for i in range((nb-1)*len(fieldTypesAndSizes)) ]
                    # need global ref to compare substructure signature to
                    # other anonstructure
                    firstField = fieldtypes.FieldType.makeStructField(
                        _record,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = fieldtypes.makeArrayField(_record, myelements)
                myfields.append(array)
                #log.debug('array of structure %s'%(array))
            elif len(fieldTypesAndSizes) == 1:  # make array of elements or
                log.debug("found array of %s",  _record._fields[0].typename.basename)
                fields = [_record._fields.pop(0) for i in range(nb)]
                array = fieldtypes.makeArrayField(_record, fields)
                myfields.append(array)
                #log.debug('array of elements %s'%(array))
            else:  # TODO DEBUG internal struct
                raise ValueError("fields patterns len is incorrect %d" % len(fieldTypesAndSizes))

        log.debug('done with aggregateFields')
        _record._fields = myfields
        # print 'final', self.fields
        return

class InlineRecordReverser(RecordReverser):
    """
    Detect record types in a large one .
    """
    def __init__(self, _context):
        super(InlineRecordReverser, self).__init__(_context, _reverse_level=200)

    def reverse_record(self, _record):
        if not _record.resolvedPointers:
            raise ValueError('I should be resolved')
        _record._dirty = True
        _record._fields.sort()
        myfields = []

        signature = _record.getTypeSignature()
        pencoder = pattern.PatternEncoder(signature, minGroupSize=2)
        patterns = pencoder.makePattern()

        txt = _record.getTypeSignature(text=True)
        p = pattern.findPatternText(txt, 1, 2)

        log.debug('substruct typeSig: %s' % txt)
        log.debug('substruct findPatterntext: %s' % p)
        log.debug('substruct came up with pattern %s' % patterns)

        # pattern is made on FieldType,
        # so we need to dequeue _record.fields at the same time to enqueue in
        # myfields
        for nb, fieldTypes in patterns:
            if nb == 1:
                field = _record._fields.pop(0)
                myfields.append(field)  # single el
                # log.debug('simple field:%s '%(field) )
            elif len(fieldTypes) > 1:  # array of subtructure DEBUG XXX TODO
                log.debug('fieldTypes:%s' % fieldTypes)
                log.debug('substructure with sig %s', ''.join([ft.sig[0] for ft in fieldTypes]))
                myelements = []
                for i in range(nb):
                    fields = [
                        _record._fields.pop(0) for i in range(
                            len(fieldTypes))]  # nb-1 left
                    # otherFields = [ _record.fields.pop(0) for i in range((nb-1)*len(fieldTypesAndSizes)) ]
                    # need global ref to compare substructure signature to
                    # other anonstructure
                    firstField = fieldtypes.FieldType.makeStructField(
                        _record,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = fieldtypes.makeArrayField(_record, myelements)
                myfields.append(array)
                # log.debug('array of structure %s'%(array))
            # make array of elements obase on same base type
            elif len(fieldTypes) == 1:
                log.debug(
                    'found array of %s' %
                    (_record._fields[0].typename.basename))
                fields = [_record._fields.pop(0) for i in range(nb)]
                array = fieldtypes.makeArrayField(_record, fields)
                myfields.append(array)
                # log.debug('array of elements %s'%(array))
            else:  # TODO DEBUG internal struct
                raise ValueError(
                    'fields patterns len is incorrect %d' %
                    (len(fieldTypes)))

        log.debug('done with findSubstructure')
        _record._fields = myfields
        # print 'final', _record.fields
        return


def refreshOne(context, ptr_value):
    """
    FIXME: usage unknown
    usage of mystruct.resolvePointers() indicates old code

    :param context:
    :param ptr_value:
    :return:
    """
    aligned = context.structures_addresses
    my_target = context.memory_handler.get_target_platform()

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
        f = mystruct.add_field(
            p_addr,
            fieldtypes.FieldType.POINTER,
            my_target.get_word_size(),
            False)
    # resolvePointers
    mystruct.resolvePointers()
    # resolvePointers
    return mystruct


def save_headers(ctx, addrs=None):
    """
    Save the python class code definition to file.

    :param ctx:
    :param addrs:
    :return:
    """
    # structs_addrs is sorted
    log.info('[+] saving headers')
    fout = file(
        config.get_cache_filename(
            config.CACHE_GENERATED_PY_HEADERS_VALUES,
            ctx.dumpname, ctx._heap_start),
        'w')
    towrite = []
    if addrs is None:
        addrs = iter(ctx.listStructuresAddresses())

    for vaddr in addrs:
        #anon = context._get_structures()[vaddr]
        anon = ctx.get_structure_for_address(vaddr)
        towrite.append(anon.to_string())
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


def reverse_heap(memory_handler, heap_addr):
    """
    Reverse a specific heap.

    :param memory_handler:
    :param heap_addr:
    :return:
    """
    from haystack.reverse import context
    log.debug('[+] Loading the memory dump for HEAP 0x%x', heap_addr)
    ctx = context.get_context_for_address(memory_handler, heap_addr)
    try:
        if not os.access(config.get_record_cache_folder_name(ctx.dumpname), os.F_OK):
            os.mkdir(config.get_record_cache_folder_name(ctx.dumpname))

        log.info("[+] Cache created in %s", config.get_cache_folder_name(ctx.dumpname))

        # try to find some logical constructs.
        log.debug('Reversing DoubleLinkedListReverser')
        doublelink = DoubleLinkedListReverser(ctx)
        doublelink.reverse()

        # decode bytes contents to find basic types.
        log.debug('Reversing Fields')
        fr = FieldReverser(ctx)
        fr.reverse()

        # save to file
        save_headers(ctx)

        # etc
    except KeyboardInterrupt as e:
        # except IOError,e:
        log.warning(e)
        log.info('[+] %d structs extracted' % (ctx.structuresCount()))
        raise e
        pass
    pass
    return ctx


def reverse_instances(dumpname):
    """
    Reverse all heaps in dumpname

    :param dumpname:
    :return:
    """
    from haystack import dump_loader
    memory_handler = dump_loader.load(dumpname)
    finder = memory_handler.get_heap_finder()
    heaps = finder.get_heap_mappings()
    for heap in heaps:
        heap_addr = heap.get_marked_heap_address()
        # reverse all fields in all records from that heap
        reverse_heap(memory_handler, heap_addr)

        ctx = memory_handler.get_cached_context_for_heap(heap)
        # identify pointer relation between structures
        log.debug('Reversing PointerFields')
        pfr = PointerFieldReverser(ctx)
        pfr.reverse()

        # graph pointer relations between structures
        log.debug('Reversing PointerGraph')
        ptrgraph = PointerGraphReverser(ctx)
        ptrgraph.reverse()
        ctx.save_structures()

        # save to file
        save_headers(ctx)

    return
