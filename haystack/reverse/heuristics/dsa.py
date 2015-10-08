#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import array

import os

from haystack.reverse import re_string
from haystack.reverse import context
from haystack.reverse.fieldtypes import FieldType, Field, PointerField
from haystack.reverse.heuristics.model import FieldAnalyser, StructureAnalyser

log = logging.getLogger('dsa')

# Field analysis related functions and classes


class ZeroFields(FieldAnalyser):

    """ checks for possible fields, aligned, with WORDSIZE zeros."""

    def make_fields(self, structure, offset, size):
        assert(
            offset %
            self._target.get_word_size() == 0)  # vaddr and offset should be aligned
        #log.debug('checking Zeroes')
        self._typename = FieldType.ZEROES
        self._zeroes = '\x00' * self._target.get_word_size()

        ret = self._find_zeroes(structure, offset, size)

        # TODO if its just a word, we should say its a small int.
        return ret

    def _find_zeroes(self, structure, offset, size):
        """ iterate over the bytes until a byte if not \x00
        """
        bytes = structure.bytes
        # print 'offset:%x blen:%d'%(offset, len(bytes))
        # print repr(bytes)
        assert((offset) % self._target.get_word_size() == 0)
        #aligned_off = (offset)%self._target_platform.get_word_size()
        start = offset
        # if aligned_off != 0: # align to next
        #    start += (self._target_platform.get_word_size() - aligned_off)
        #    size    -= (self._target_platform.get_word_size() - aligned_off)
        # iterate
        matches = array.array('i')
        for i in range(start, start + size, self._target.get_word_size()):
            # PERF TODO: bytes or struct test ?
            # print repr(bytes[start+i:start+i+self._target_platform.get_word_size()])
            if bytes[
                    start + i:start + i + self._target.get_word_size()] == self._zeroes:
                matches.append(start + i)
                # print matches
        # collate
        if len(matches) == 0:
            return []
        # lets try to get fields
        fields = []
        # first we need to collate neighbors
        collates = list()
        prev = matches[0] - self._target.get_word_size()
        x = []
        # PERF TODO: whats is algo here
        for i in matches:
            if i - self._target.get_word_size() == prev:
                x.append(i)
            else:
                collates.append(x)
                x = [i]
            prev = i
        collates.append(x)
        # log.debug(collates)
        # we now have collated, lets create fields
        for field in collates:
            flen = len(field)
            if flen > 1:
                size = self._target.get_word_size() * flen
            elif flen == 1:
                size = self._target.get_word_size()
            else:
                continue
            # make a field
            fields.append(
                Field(
                    structure,
                    start +
                    field[0],
                    self._typename,
                    size,
                    False))
        # we have all fields
        return fields


class UTF16Fields(FieldAnalyser):

    """
    rfinds utf-16-ascii and ascii 7bit

    """

    def make_fields(self, structure, offset, size):
        assert(offset % self._target.get_word_size() == 0)  # vaddr and offset should be aligned
        #log.debug('checking String')
        fields = []
        bytes = structure.bytes
        while size > self._target.get_word_size():
            # print 're_string.rfind_utf16(bytes, %d, %d)'%(offset,size)
            # we force aligned results only.
            index = re_string.rfind_utf16(bytes, offset, size, True, self._target.get_word_size())
            if index > -1:
                f = Field(structure, offset + index, FieldType.STRING16, size - index, False)
                # print repr(structure.bytes[f.offset:f.offset+f.size])
                fields.append(f)
                size = index  # reduce unknown field in prefix
            else:
                size -= self._target.get_word_size()  # reduce unkown field
        # look in head
        return fields


class PrintableAsciiFields(FieldAnalyser):

    """ finds printable ascii fields """

    def make_fields(self, structure, offset, size):
        assert(
            offset %
            self._target.get_word_size() == 0)  # vaddr and offset should be aligned
        #log.debug('checking String')
        fields = []
        bytes = structure.bytes
        while size >= self._target.get_word_size():
            # print 're_string.find_ascii(bytes, %d, %d)'%(offset,size)
            index, ssize = re_string.find_ascii(bytes, offset, size)
            if index == 0:
                if (ssize < size) and bytes[offset + index + ssize] == '\x00':  # space for a \x00
                    ssize += 1
                    f = Field(structure, offset + index, FieldType.STRINGNULL, ssize, False)
                else:
                    f = Field(structure, offset + index, FieldType.STRING, ssize, False)
                # print repr(structure.bytes[f.offset:f.offset+f.size])
                fields.append(f)
                size -= ssize  # reduce unknown field
                offset += ssize
                if ssize % self._target.get_word_size():
                    rest = self._target.get_word_size() - ssize % self._target.get_word_size()
                    size -= rest  # goto next aligned
                    offset += rest
            else:
                size -= self._target.get_word_size()  # reduce unkown field
                offset += self._target.get_word_size()
        # look in head
        return fields


class PointerFields(FieldAnalyser):

    """ TODO tests """
    """ looks at a word for a pointer value"""

    def make_fields(self, structure, offset, size):
        # iterate on all offsets . NOT assert( size ==
        # self._target_platform.get_word_size())
        assert(
            offset %
            self._target.get_word_size() == 0)  # vaddr and offset should be aligned
        log.debug('checking Pointer')
        bytes = structure.bytes
        fields = []
        ctypes_utils = self._target.get_target_ctypes_utils()
        while size >= self._target.get_word_size():
            value = ctypes_utils.unpackWord(bytes[offset:offset + self._target.get_word_size()])
            # check if pointer value is in range of _memory_handler and set self.comment to pathname value of pointer
            # TODO : if bytes 1 & 3 == \x00, maybe utf16 string
            if not self._memory_handler.is_valid_address(value):
                size -= self._target.get_word_size()
                offset += self._target.get_word_size()
                continue
            # we have a pointer
            log.debug('checkPointer offset:%s value:%s' % (offset, hex(value)))
            field = PointerField(structure, offset, FieldType.POINTER, self._target.get_word_size(), False)
            field.value = value
            # TODO: leverage the context._function_names
            # if value in structure._context._function_names:
            #    field.comment = ' %s::%s' % (os.path.basename(self._memory_handler.get_mapping_for_address(value).pathname),
            #                                 structure._context._function_names[value])
            # else:
            #    field.comment = self._memory_handler.get_mapping_for_address(value).pathname
            field.comment = self._memory_handler.get_mapping_for_address(value).pathname

            fields.append(field)
            size -= self._target.get_word_size()
            offset += self._target.get_word_size()
        return fields


class IntegerFields(FieldAnalyser):

    """ looks at a word for a small int value"""

    def make_fields(self, structure, offset, size):
        # iterate on all offsets . NOT assert( size ==
        # self._target_platform.get_word_size())
        assert(
            offset %
            self._target.get_word_size() == 0)  # vaddr and offset should be aligned
        #log.debug('checking Integer')
        bytes = structure.bytes
        fields = []
        while size >= self._target.get_word_size():
            # print 'checking >'
            field = self.checkSmallInt(structure, bytes, offset)
            if field is None:
                # print 'checking <'
                field = self.checkSmallInt(structure, bytes, offset, '>')
            # we have a field smallint
            if field is not None:
                fields.append(field)
            size -= self._target.get_word_size()
            offset += self._target.get_word_size()
        return fields

    def checkSmallInt(self, structure, bytes, offset, endianess='<'):
        """ check for small value in signed and unsigned forms """
        val = self._target.get_target_ctypes_utils().unpackWord(
            bytes[
                offset:offset +
                self._target.get_word_size()],
            endianess)
        # print endianess, val
        if val < 0xffff:
            field = Field(
                structure,
                offset,
                FieldType.SMALLINT,
                self._target.get_word_size(),
                False)
            field.value = val
            field.endianess = endianess
            return field
        # check signed int
        elif ((2 ** (self._target.get_word_size() * 8) - 0xffff) < val):
            field = Field(
                structure,
                offset,
                FieldType.SIGNED_SMALLINT,
                self._target.get_word_size(),
                False)
            field.value = val
            field.endianess = endianess
            return field
        return None


class DSASimple(StructureAnalyser):

    """ Simple structure analyzer that leverage simple type recognition heuristics.
    For all aligned offset, try to apply the following heuristics :
    ZeroFields: if the word is null
    UTF16Fields: if the offset contains utf-16 data
    PrintableAsciiFields: if the offset starts a printable ascii string
    IntegerFields: if the word value is small ( |x| < 65535 )
    PointerFields: if the word if a possible pointer value

    If the word content does not match theses heuristics, tag the fiel has unknown.
    """

    def __init__(self, memory_handler):
        super(DSASimple, self).__init__(memory_handler)
        self.zero_a = ZeroFields(self._memory_handler)
        self.ascii_a = PrintableAsciiFields(self._memory_handler)
        self.utf16_a = UTF16Fields(self._memory_handler)
        self.int_a = IntegerFields(self._memory_handler)
        self.ptr_a = PointerFields(self._memory_handler)

    def analyze_fields(self, structure):
        structure.reset()
        fields, gaps = self._analyze(structure)
        structure.add_fields(fields)
        structure.add_fields(gaps)  # , FieldType.UNKNOWN
        structure.set_resolved()
        return structure

    def _analyze(self, structure):
        slen = len(structure)
        offset = 0
        # call on analyzers
        fields = []
        nb = -1
        gaps = [Field(structure, 0, FieldType.UNKNOWN, len(structure), False)]

        # find zeroes
        # find strings
        # find smallints
        # find pointers
        for analyser in [self.zero_a, self.utf16_a, self.ascii_a, self.int_a, self.ptr_a]:
            log.debug("analyzing with %s", analyser)
            for field in gaps:
                if field.padding:
                    fields.append(field)
                    continue
                log.debug('Using %s on %d:%d', analyser.__class__.__name__, field.offset, field.offset + len(field))
                new_fields = analyser.make_fields(structure, field.offset, len(field))
                fields.extend(new_fields)
                for f1 in new_fields:
                    log.debug('new_field %s', f1)
                # print fields
            if len(fields) != nb:  # no change in fields, keep gaps
                nb = len(fields)
                gaps = self._make_gaps(structure, fields)
            if len(gaps) == 0:
                return fields, gaps
        return fields, gaps

    def _make_gaps(self, structure, fields):
        fields.sort()
        gaps = []
        nextoffset = 0
        for i, f in enumerate(fields):
            if f.offset > nextoffset:  # add temp padding field
                self._aligned_gaps(structure, f.offset, nextoffset, gaps)
            elif f.offset < nextoffset:
                log.debug(structure)
                log.debug(f)
                log.debug('%s < %s ' % (f.offset, nextoffset))
                log.debug(fields[i + 1])
                log.error("need to TU the fields gap with utf8 text")
                assert(False)  # f.offset < nextoffset # No overlaps authorised
                # fields.remove(f)
            # do next field
            nextoffset = f.offset + len(f)
        # conclude on QUEUE insertion
        lastfield_size = len(structure) - nextoffset
        if lastfield_size > 0:
            if lastfield_size < self._target.get_word_size():
                gap = Field(structure, nextoffset, FieldType.UNKNOWN, lastfield_size, True)
                log.debug('_make_gaps: adding last field at offset %d:%d', gap.offset, gap.offset + len(gap))
                gaps.append(gap)
            else:
                self._aligned_gaps(structure, len(structure), nextoffset, gaps)
        return gaps

    def _aligned_gaps(self, structure, endoffset, nextoffset, gaps):
        """ if nextoffset is aligned
                    add a gap to gaps, or
                if nextoffset is not aligned
                    add (padding + gap) to gaps
                 """
        if nextoffset % self._target.get_word_size() == 0:
            gap = Field(structure, nextoffset, FieldType.UNKNOWN, endoffset - nextoffset, False)
            log.debug('_make_gaps: adding field at offset %d:%d', gap.offset, gap.offset + len(gap))
            gaps.append(gap)
        else:
            # unaligned field should be splitted
            s1 = self._target.get_word_size() - nextoffset % self._target.get_word_size()
            gap1 = Field(structure, nextoffset, FieldType.UNKNOWN, s1, True)
            log.debug('_make_gaps: Unaligned field at offset %d:%d', gap1.offset, gap1.offset + len(gap1))
            gaps.append(gap1)
            if nextoffset + s1 < endoffset:
                gap2 = Field(structure, nextoffset + s1, FieldType.UNKNOWN, endoffset - nextoffset - s1, False)
                log.debug('_make_gaps: adding field at offset %d:%d', gap2.offset, gap2.offset + len(gap2))
                gaps.append(gap2)
        return


class EnrichedPointerFields(StructureAnalyser):

    """ For all pointer fields in a structure,
    try to enrich the field name with information about the child structure.

    All structure should have been Analysed, otherwise,
    results are not going to be untertaining.
    """

    def analyze_fields(self, structure):
        """ @returns structure, with enriched info on pointer fields.
        For pointer fields value:
        (-) if pointer value is in _memory_handler ( well it is... otherwise it would not be a pointer.)
        + if value is unaligned, mark it as cheesy
        + ask _memory_handler for the context for that value
            - if context covers a data lib, it would give function names, .data , .text ( CodeContext )
            - if context covers a HEAP/heap extension (one context for multiple mmap possible) it would give structures
        + ask context for the target structure or code info
            - if retobj is structure, enrich pointer with info
        """
        # If you want to cache resolved infos, it still should be decided by
        # the caller
        pointerFields = structure.getPointerFields()
        log.debug('got %d pointerfields' % (len(pointerFields)))
        for field in pointerFields:
            value = field.value
            field.set_child_addr(value)  # default
            # FIXME field.set_resolved() # What ?
            # + if value is unaligned, mark it as cheesy
            if value % self._target.get_word_size():
                field.set_uncertainty('Unaligned pointer value')
            # + ask _memory_handler for the context for that value
            try:
                ctx = context.get_context_for_address(self._memory_handler, value)  # no error expected.
                #log.warning('value: 0x%0.8x ctx.heap: 0x%0.8x'%(value, ctx.heap.start))
                # print '** ST id', id(structure), hex(structure._vaddr)
                # + ask context for the target structure or code info
            except ValueError as e:
                log.debug('target to non heap mmaps is not implemented')
                m = self._memory_handler.get_mapping_for_address(value)
                field.set_child_desc(
                    'ext_lib @%0.8x %s' %
                    (m.start, m.pathname))
                field._ptr_to_ext_lib = True
                field.set_child_ctype('void')  # TODO: Function pointer ?
                field.set_name('ptr_ext_lib_%d' % (field.offset))
                continue
            tgt = None
            try:
                # get enclosing structure @throws KeyError
                tgt = ctx.getStructureForOffset(value)
            # there is no child structure member at pointed value.
            except (IndexError, ValueError) as e:
                log.debug(
                    'there is no child structure enclosing pointed value %0.8x - %s' %
                    (value, e))
                field.set_child_desc('MemoryHandler management space')
                field.set_child_ctype('void')
                field.set_name('ptr_void')
                continue
            # structure found
            # we always point on structure, not field
            field.set_child_addr(tgt._vaddr)
            offset = value - tgt._vaddr
            try:
                tgt_field = tgt.get_field_at_offset(offset)  # @throws IndexError
            except IndexError as e:  # there is no field right there
                log.debug('there is no field at pointed value %0.8x. May need splitting byte field - %s', value, e)
                field.set_child_desc('Badly reversed field')
                field.set_child_ctype('void')
                field.set_name('ptr_void')
                continue
            # do not put exception for field 0. structure name should appears
            # anyway.
            field.set_child_desc(
                '%s.%s' %
                (tgt.get_name(), tgt_field.get_name()))
            # TODO:
            # do not complexify code by handling target field type,
            # lets start with simple structure type pointer,
            # later we would need to use tgt_field.ctypes depending on field
            # offset
            field.set_child_ctype(tgt.get_name())
            field.set_name('%s_%s' % (tgt.get_name(), tgt_field.get_name()))
            # all
        return

    def get_unresolved_children(self, structure):
        """ returns all children that are not fully analyzed yet."""
        pointerFields = structure.getPointerFields()
        children = []
        for field in pointerFields:
            try:
                tgt = structure._context.get_structure_for_address(field.value)
                if not tgt.is_resolved():  # fields have not been decoded yet
                    children.append(tgt)
            except KeyError as e:
                pass
        return children


class IntegerArrayFields(StructureAnalyser):

    """ TODO """

    def make_fields(self, structure, offset, size):
        # this should be last resort
        bytes = self.struct.bytes[self.offset:self.offset + self.size]
        size = len(bytes)
        if size < 4:
            return False
        ctr = collections.Counter(
            [bytes[i:i + self._target.get_word_size()] for i in range(len(bytes))])
        floor = max(1, int(size * .1))  # 10 % variation in values
        #commons = [ c for c,nb in ctr.most_common() if nb > 2 ]
        commons = ctr.most_common()
        if len(commons) > floor:
            return False  # too many different values
        # few values. it migth be an array
        self.size = size
        self.values = bytes
        self.comment = '10%% var in values: %s' % (
            ','.join([repr(v) for v, nb in commons]))
        return True
