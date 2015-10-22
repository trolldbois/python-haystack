#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import array
import collections

from haystack.reverse import re_string
from haystack.reverse import fieldtypes
from haystack.reverse import structure
from haystack.reverse.heuristics import model

log = logging.getLogger('dsa')

# fieldtypes.Field analysis related functions and classes


class ZeroFields(model.FieldAnalyser):
    """ checks for possible fields, aligned, with WORDSIZE zeros."""
    def make_fields(self, structure, offset, size):
        assert(offset % self._word_size == 0)  # vaddr and offset should be aligned
        # log.debug('checking Zeroes')
        self._typename = fieldtypes.ZEROES
        self._zeroes = '\x00' * self._word_size

        ret = self._find_zeroes(structure, offset, size)

        # TODO if its just a word, we should say its a small int.
        return ret

    def _find_zeroes(self, structure, offset, size):
        """ iterate over the bytes until a byte if not \x00        """
        bytes = structure.bytes
        # print 'offset:%x blen:%d'%(offset, len(bytes))
        # print repr(bytes)
        assert(offset % self._word_size == 0)
        # aligned_off = (offset)%self._target_platform.get_word_size()
        start = offset
        # if aligned_off != 0: # align to next
        #    start += (self._target_platform.get_word_size() - aligned_off)
        #    size    -= (self._target_platform.get_word_size() - aligned_off)
        # iterate
        matches = array.array('i')
        for i in range(start, start + size, self._word_size):
            # PERF TODO: bytes or struct test ?
            # print repr(bytes[start+i:start+i+self._target_platform.get_word_size()])
            if bytes[start + i:start + i + self._word_size] == self._zeroes:
                matches.append(start + i)
                # print matches
        # collate
        if len(matches) == 0:
            return []
        # lets try to get fields
        fields = []
        # first we need to collate neighbors
        collates = list()
        prev = matches[0] - self._word_size
        x = []
        # PERF TODO: whats is algo here
        for i in matches:
            if i - self._word_size == prev:
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
                size = self._word_size * flen
            elif flen == 1:
                size = self._word_size
            else:
                continue
            # make a field
            _offset = start + field[0]
            fields.append(fieldtypes.Field('zerroes_%d' % _offset, _offset, self._typename, size, False))
        # we have all fields
        return fields


class UTF16Fields(model.FieldAnalyser):
    """
    rfinds utf-16-ascii and ascii 7bit
    """
    def make_fields(self, structure, offset, size):
        assert(offset % self._word_size == 0)  # vaddr and offset should be aligned
        #log.debug('checking String')
        fields = []
        bytes = structure.bytes
        while size > self._word_size:
            # print 're_string.rfind_utf16(bytes, %d, %d)'%(offset,size)
            # we force aligned results only.
            index = re_string.rfind_utf16(bytes, offset, size, True, self._word_size)
            if index > -1:
                _offset = offset + index
                f = fieldtypes.Field('utf16_%d' % _offset, _offset, fieldtypes.STRING16, size - index, False)
                # print repr(structure.bytes[f.offset:f.offset+f.size])
                fields.append(f)
                size = index  # reduce unknown field in prefix
            else:
                size -= self._word_size  # reduce unkown field
        # look in head
        return fields


class PrintableAsciiFields(model.FieldAnalyser):

    """ finds printable ascii fields """

    def make_fields(self, structure, offset, size):
        assert(
            offset %
            self._word_size == 0)  # vaddr and offset should be aligned
        #log.debug('checking String')
        fields = []
        bytes = structure.bytes
        while size >= self._word_size:
            # print 're_string.find_ascii(bytes, %d, %d)'%(offset,size)
            index, ssize = re_string.find_ascii(bytes, offset, size)
            if index == 0:
                _offset =  offset + index
                if (ssize < size) and bytes[offset + index + ssize] == '\x00':  # space for a \x00
                    ssize += 1
                    f = fieldtypes.Field('strnull_%d' % _offset, _offset, fieldtypes.STRINGNULL, ssize, False)
                else:
                    f = fieldtypes.Field('str_%d' % _offset, _offset, fieldtypes.STRING, ssize, False)
                # print repr(structure.bytes[f.offset:f.offset+f.size])
                fields.append(f)
                size -= ssize  # reduce unknown field
                offset += ssize
                if ssize % self._word_size:
                    rest = self._word_size - ssize % self._word_size
                    size -= rest  # goto next aligned
                    offset += rest
            else:
                size -= self._word_size  # reduce unkown field
                offset += self._word_size
        # look in head
        return fields


class PointerFields(model.FieldAnalyser):
    """ looks at a word for a pointer value"""
    def make_fields(self, structure, offset, size):
        # iterate on all offsets . NOT assert( size ==
        # self._target_platform.get_word_size())
        assert(offset % self._word_size == 0)  # vaddr and offset should be aligned
        log.debug('checking Pointer')
        bytes = structure.bytes
        fields = []
        ctypes_utils = self._target.get_target_ctypes_utils()
        while size >= self._word_size:
            value = ctypes_utils.unpackWord(bytes[offset:offset + self._word_size])
            # check if pointer value is in range of _memory_handler and set self.comment to pathname value of pointer
            # TODO : if bytes 1 & 3 == \x00, maybe utf16 string
            if not self._memory_handler.is_valid_address(value):
                size -= self._word_size
                offset += self._word_size
                continue
            # we have a pointer
            log.debug('checkPointer offset:%s value:%s' % (offset, hex(value)))
            field = fieldtypes.PointerField('ptr_%d' % offset, offset, self._word_size)
            # TODO: leverage the context._function_names
            # if value in structure._context._function_names:
            #    field.comment = ' %s::%s' % (os.path.basename(self._memory_handler.get_mapping_for_address(value).pathname),
            #                                 structure._context._function_names[value])
            # else:
            #    field.comment = self._memory_handler.get_mapping_for_address(value).pathname
            field.comment = self._memory_handler.get_mapping_for_address(value).pathname

            fields.append(field)
            size -= self._word_size
            offset += self._word_size
        return fields


class IntegerFields(model.FieldAnalyser):

    """ looks at a word for a small int value"""

    def make_fields(self, structure, offset, size):
        # iterate on all offsets . NOT assert( size ==
        # self._target_platform.get_word_size())
        assert(offset % self._word_size == 0)  # vaddr and offset should be aligned
        # log.debug('checking Integer')
        my_bytes = structure.bytes
        fields = []
        while size >= self._word_size:
            # print 'checking >'
            field = self.check_small_integers(my_bytes, offset)
            if field is None:
                # print 'checking <'
                field = self.check_small_integers(my_bytes, offset, '>')
            # we have a field smallint
            if field is not None:
                fields.append(field)
            size -= self._word_size
            offset += self._word_size
        return fields

    def check_small_integers(self, my_bytes, offset, endianess='<'):
        """ check for small value in signed and unsigned forms """
        data = my_bytes[offset:offset + self._word_size]
        val = self._target.get_target_ctypes_utils().unpackWord(data, endianess)
        # print endianess, val
        if val < 0xffff:
            field = fieldtypes.Field('small_int_%d' % offset, offset, fieldtypes.SMALLINT, self._word_size, False)
            # FIXME
            field.value = val
            field.endianess = endianess
            return field
        # check signed int
        elif (2 ** (self._word_size * 8) - 0xffff) < val:
            field = fieldtypes.Field('small_signed_int_%d' % offset, offset, fieldtypes.SIGNED_SMALLINT, self._word_size, False)
            # FIXME
            field.value = val
            field.endianess = endianess
            return field
        return None


class FieldReverser(model.AbstractReverser):
    """
    Decode each record by asserting simple basic types from the byte content.

    Simple structure analyzer that leverage simple type recognition heuristics.
    For all aligned offset, try to apply the following heuristics :
    ZeroFields: if the word is null
    UTF16Fields: if the offset contains utf-16 data
    PrintableAsciiFields: if the offset starts a printable ascii string
    IntegerFields: if the word value is small ( |x| < 65535 )
    PointerFields: if the word if a possible pointer value

    If the word content does not match theses heuristics, tag the fiel has unknown.
    """
    REVERSE_LEVEL = 10

    def __init__(self, memory_handler):
        super(FieldReverser, self).__init__(memory_handler)
        self.zero_a = ZeroFields(self._memory_handler)
        self.ascii_a = PrintableAsciiFields(self._memory_handler)
        self.utf16_a = UTF16Fields(self._memory_handler)
        self.int_a = IntegerFields(self._memory_handler)
        self.ptr_a = PointerFields(self._memory_handler)

    def reverse_record(self, _context, _record):
        _record.reset()
        fields, gaps = self._analyze(_record)
        # _record.add_fields(fields)
        # _record.add_fields(gaps)  # , fieldtypes.UNKNOWN
        _record_type = structure.RecordType('struct_%x' % _record.address, len(_record), fields+gaps)
        _record.set_record_type(_record_type)
        _record.set_reverse_level(self._reverse_level)
        return _record

    def _analyze(self, _record):
        slen = len(_record)
        offset = 0
        # call on analyzers
        fields = []
        nb = -1
        gaps = [fieldtypes.Field('unknown_0', 0, fieldtypes.UNKNOWN, len(_record), False)]

        _record.set_reverse_level(10)

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
                new_fields = analyser.make_fields(_record, field.offset, len(field))
                fields.extend(new_fields)
                for f1 in new_fields:
                    log.debug('new_field %s', f1)
                # print fields
            if len(fields) != nb:  # no change in fields, keep gaps
                nb = len(fields)
                gaps = self._make_gaps(_record, fields)
            if len(gaps) == 0:
                return fields, gaps
        return fields, gaps

    def _make_gaps(self, _record, fields):
        fields.sort()
        gaps = []
        nextoffset = 0
        for i, f in enumerate(fields):
            if f.offset > nextoffset:  # add temp padding field
                self._aligned_gaps(_record, f.offset, nextoffset, gaps)
            elif f.offset < nextoffset:
                log.debug(_record)
                log.debug(f)
                log.debug('%s < %s ' % (f.offset, nextoffset))
                log.debug(fields[i + 1])
                log.error("need to TU the fields gap with utf8 text")
                assert(False)  # f.offset < nextoffset # No overlaps authorised
                # fields.remove(f)
            # do next field
            nextoffset = f.offset + len(f)
        # conclude on QUEUE insertion
        lastfield_size = len(_record) - nextoffset
        if lastfield_size > 0:
            if lastfield_size < self._word_size:
                gap = fieldtypes.Field('gap_%d' % nextoffset, nextoffset, fieldtypes.UNKNOWN, lastfield_size, True)
                log.debug('_make_gaps: adding last field at offset %d:%d', gap.offset, gap.offset + len(gap))
                gaps.append(gap)
            else:
                self._aligned_gaps(_record, len(_record), nextoffset, gaps)
        return gaps

    def _aligned_gaps(self, _record, endoffset, nextoffset, gaps):
        """ if nextoffset is aligned
                    add a gap to gaps, or
                if nextoffset is not aligned
                    add (padding + gap) to gaps
                 """
        if nextoffset % self._word_size == 0:
            gap = fieldtypes.Field('gap_%d' % nextoffset, nextoffset, fieldtypes.UNKNOWN, endoffset - nextoffset, False)
            log.debug('_make_gaps: adding field at offset %d:%d', gap.offset, gap.offset + len(gap))
            gaps.append(gap)
        else:
            # unaligned field should be splitted
            s1 = self._word_size - nextoffset % self._word_size
            gap1 = fieldtypes.Field('gap_%d' % nextoffset, nextoffset, fieldtypes.UNKNOWN, s1, True)
            log.debug('_make_gaps: Unaligned field at offset %d:%d', gap1.offset, gap1.offset + len(gap1))
            gaps.append(gap1)
            if nextoffset + s1 < endoffset:
                gap2 = fieldtypes.Field('gap_%d' % (nextoffset + s1), nextoffset + s1, fieldtypes.UNKNOWN, endoffset - nextoffset - s1, False)
                log.debug('_make_gaps: adding field at offset %d:%d', gap2.offset, gap2.offset + len(gap2))
                gaps.append(gap2)
        return


class IntegerArrayFields(model.FieldAnalyser):

    """ TODO """

    def make_fields(self, _record, offset, size):
        # this should be last resort
        bytes = _record.bytes[offset:offset + self.size]
        size = len(bytes)
        if size < 4:
            return False
        ctr = collections.Counter([bytes[i:i + self._word_size] for i in range(len(bytes))])
        floor = max(1, int(size * .1))  # 10 % variation in values
        #commons = [ c for c,nb in ctr.most_common() if nb > 2 ]
        commons = ctr.most_common()
        if len(commons) > floor:
            return False  # too many different values
        # few values. it migth be an array
        self.size = size
        # FIXME
        self.values = bytes
        self.comment = '10%% var in values: %s' % (','.join([repr(v) for v, nb in commons]))
        return True
