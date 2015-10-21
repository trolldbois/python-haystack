# -*- coding: utf-8 -*-

import logging

from haystack.reverse import context
from haystack.reverse.heuristics import model

log = logging.getLogger("pointertypes")


class PointerFieldReverser(model.AbstractReverser):
    """
    Identify pointer fields and their target structure.

    For all pointer fields in a structure,
    try to enrich the field name with information about the child structure.

    All structure should have been Analysed, otherwise,
    results are not going to be untertaining.
    """
    REVERSE_LEVEL = 50

    def reverse_record(self, _context, _record):
        """
        @returns structure, with enriched info on pointer fields.
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
        pointer_fields = [field for field in _record.get_fields() if field.is_pointer()]
        log.debug('got %d pointerfields', len(pointer_fields))
        for field in pointer_fields:
            value = field.get_value(_record)
            field.set_child_addr(value)  # default
            # FIXME field.set_resolved() # What ?
            # + if value is unaligned, mark it as cheesy
            if value % self._target.get_word_size():
                field.set_uncertainty('Unaligned pointer value')
            # + ask _memory_handler for the context for that value
            try:
                ctx = context.get_context_for_address(self._memory_handler, value)  # no error expected.
                # + ask context for the target structure or code info
            except ValueError as e:
                # value is a pointer, but not to a heap.
                m = self._memory_handler.get_mapping_for_address(value)
                field.set_child_desc('ext_lib @%0.8x %s' % (m.start, m.pathname))
                field._ptr_to_ext_lib = True
                field.set_child_ctype('void')
                # TODO: Function pointer ?
                field.set_name('ptr_ext_lib_%d' % field.offset)
                continue
            tgt = None
            try:
                # get enclosing structure @throws KeyError
                tgt = ctx.get_record_at_address(value)
            # there is no child structure member at pointed value.
            except (IndexError, ValueError) as e:
                log.debug('there is no child structure enclosing pointed value %0.8x - %s', value, e)
                field.set_child_desc('MemoryHandler management space')
                field.set_child_ctype('void')
                field.set_name('ptr_void')
                continue
            # structure found
            log.debug('Looking at child id:0x%x str:%s', tgt.address, tgt.to_string())
            # we always point on structure, not field
            field.set_child_addr(tgt.address)
            offset = value - tgt.address
            try:
                tgt_field = tgt.get_field_at_offset(offset)  # @throws IndexError
            except IndexError as e:
                # there is no field right there
                log.debug('there is no field at pointed value %0.8x. May need splitting byte field - %s', value, e)
                field.set_child_desc('Badly reversed field')
                field.set_child_ctype('void')
                field.set_name('ptr_void')
                continue
            # do not put exception for field 0. structure name should appears
            # anyway.
            field.set_child_desc('%s.%s' % (tgt.get_name(), tgt_field.get_name()))
            # TODO:
            # do not complexify code by handling target field type,
            # lets start with simple structure type pointer,
            # later we would need to use tgt_field.ctypes depending on field
            # offset
            field.set_child_ctype(tgt.get_name())
            field.set_name('%s_%s' % (tgt.get_name(), tgt_field.get_name()))
            # all

        _record.set_reverse_level(self._reverse_level)
        return
