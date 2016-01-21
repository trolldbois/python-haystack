# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import time

from haystack.abc import interfaces as hi
from haystack.reverse.heuristics import interfaces as hri
from haystack.reverse import context


log = logging.getLogger('model')


class AbstractReverser(hri.IReverser):

    REVERSE_LEVEL = 0

    def __init__(self, _memory_handler, reverse_level=None):
        if not isinstance(_memory_handler, hi.IMemoryHandler):
            raise TypeError('memory_handler should be an IMemoryHandler')
        self._memory_handler = _memory_handler
        if reverse_level is None:
            self._reverse_level = self.REVERSE_LEVEL
        else:
            self._reverse_level = reverse_level
        self._target = self._memory_handler.get_target_platform()
        self._word_size = self._target.get_word_size()
        # metadata
        self._t0 = self._t1 = self._nb_reversed = self._nb_from_cache = 0
        self._fout = None
        self._towrite = None

    def get_reverse_level(self):
        return self._reverse_level

    def _iterate_contexts(self):
        """ Override to change the list of contexts """
        # for ctx in self._memory_handler.get_cached_context():
        finder = self._memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        # we need to get then either from memory_handler or from file or from scratch
        for heap_walker in walkers:
            ctx = context.get_context_for_address(self._memory_handler, heap_walker.get_heap_address())
            yield ctx

    def _iterate_records(self, _context):
        """ Override to change the list of record for this _context """
        for _record in _context.listStructures():
            if _record.get_reverse_level() >= self.get_reverse_level():
                continue
            yield _record

    def _iterate_fields(self, _context, _record):
        """ Override to change the list of field for this _record """
        for _field in _record.get_fields():
            yield _field

    def reverse(self):
        """
        Go over each record and call the reversing process.
        Wraps around some time-based function to ease the wait.
        Saves the context to cache at the end.
        """
        log.info('[+] %s: START', self)
        # run the reverser
        for _context in self._iterate_contexts():
            self._t0 = time.time()
            self._t1 = self._t0
            self._nb_reversed = 0
            self._nb_from_cache = 0
            # call
            self.reverse_context(_context)
            # save the context
            _context.save()
        # closing statements
        total = self._nb_from_cache + self._nb_reversed
        ts = time.time() - self._t0
        log.debug('[+] %s: END %d records in %2.0fs (new:%d,cache:%d)', self, total, ts, self._nb_reversed, self._nb_from_cache)
        ####
        return

    def reverse_context(self, _context):
        """
        Go over each record and call the reversing process.
        Wraps around some time-based function to ease the wait.
        Saves the context to cache at the end.
        """
        log.info('[+] %s: START on heap 0x%x', self, _context._heap_start)
        t0 = time.time()
        for _record in self._iterate_records(_context):
            # call the heuristic
            self.reverse_record(_context, _record)
            # can call get_record_count because of loop
            # #self._callback(total=_context.get_record_count())
        # closing statements
        total = self._nb_from_cache + self._nb_reversed
        ts = time.time() - t0
        log.debug('[+] %s: END time:%2.0fs Heap:0x%x records:%d (new:%d,cache:%d)', self, ts, _context._heap_start, ts, self._nb_reversed, self._nb_from_cache)
        return

    def reverse_record(self, _context, _record):
        """
        Subclass implementation of the reversing process

        Should set _reverse_level of _record.
        """
        if _record.get_reverse_level() >= self.get_reverse_level():
            # ignore this record. its already reversed.
            self._nb_from_cache += 1
        else:
            self._nb_reversed += 1
            for _field in self._iterate_fields(_context, _record):
                self.reverse_field(_context, _record, _field)
            # set our new reserve level
            _record.set_reverse_level(self.get_reverse_level())
            # sate the _record
            _record.saveme(_context)
        return

    def reverse_field(self, _context, _record, _field):
        """
        Subclass implementation of the reversing process
        """
        return

    def _callback(self, total):
        """ callback for human use """
        # every 30 secs, print a statement, save text repr to file.
        if time.time() - self._t1 > 30:
            t1 = time.time()
            rate = (t1 - self._t0) / (1 + self._nb_reversed + self._nb_from_cache)
            _ttg = (total - (self._nb_from_cache + self._nb_reversed)) * rate
            log.info('%2.2f seconds to go (new:%d,cache:%d)', _ttg, self._nb_reversed, self._nb_from_cache)
        return

    def __str__(self):
        return '<%s>' % self.__class__.__name__


class WriteRecordToFile(AbstractReverser):

    def reverse_context(self, _context):
        self._fout = file(_context.get_filename_cache_headers(), 'w')
        self._towrite = []
        super(WriteRecordToFile, self).reverse_context(_context)
        self._write()
        self._fout.close()

    def reverse_record(self, _context, _record):
        super(WriteRecordToFile, self).reverse_record(_context, _record)
        # output headers
        self._towrite.append(_record.to_string())

    def _write(self):
        self._fout.write('\n'.join(self._towrite))
        self._towrite = []
        pass


class FieldAnalyser(object):
    """

    """
    def __init__(self, memory_handler):
        if not isinstance(memory_handler, hi.IMemoryHandler):
            raise TypeError('memory_handler should be an IMemoryHandler')
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()
        self._word_size = self._target.get_word_size()

    def make_fields(self, structure, offset, size):
        """
        @param structure: the structure object, with a bytes()
        @param offset: the offset of the field to analyze
        @param size: the size of said field

        @return False, or [Field(), ]
        """
        raise NotImplementedError('This should be implemented.')


