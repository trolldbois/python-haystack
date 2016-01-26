# -*- coding: utf-8 -*-

import logging

from haystack.reverse import context
from haystack.reverse.heuristics import model
from haystack.reverse.heuristics import radare

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

    def __init__(self, _memory_handler):
        super(PointerFieldReverser, self).__init__(_memory_handler)
        # process_context = self._memory_handler.get_reverse_context()
        # self.__functions_pointers = process_context.get_functions_pointers()

    def reverse_record(self, _context, _record):
        """
        @returns structure, with enriched info on pointer fields.
        For pointer fields value:
        (-) if pointer value is in _memory_handler ( well it is... otherwise it would not be a pointer.)
        + if value is unaligned, mark it as cheesy
        + ask _memory_handler for the context for that value
            - if context covers a data lib, it would give function names, .data , .text ( CodeContext )
            - if context covers a HEAP/heap extension (one context for multiple mmap possible) it would give allocators
        + ask context for the target structure or code info
            - if retobj is structure, enrich pointer with info
        """
        # If you want to cache resolved infos, it still should be decided by
        # the caller
        pointer_fields = [field for field in _record.get_fields() if field.is_pointer()]
        log.debug('got %d pointer fields', len(pointer_fields))
        for field in pointer_fields:
            value = _record.get_value_for_field(field)
            field.set_pointee_addr(value)  # default
            # FIXME field.set_resolved() # What ?
            # + if value is unaligned, mark it as cheesy
            if value % self._target.get_word_size():
                field.comment = 'Unaligned pointer value'
            # + ask _memory_handler for the context for that value
            try:
                ctx = context.get_context_for_address(self._memory_handler, value)  # no error expected.
                # + ask context for the target structure or code info
            except ValueError as e:
                # value is a pointer, but not to a heap.
                m = self._memory_handler.get_mapping_for_address(value)
                # field.set_child_desc('ext_lib @%0.8x %s' % (m.start, m.pathname))
                field.set_pointer_to_ext_lib()
                field.set_pointee_ctype('void')
                # TODO: Function pointer ?
                field.name = 'ptr_ext_lib_%d' % field.offset
                # if value in self.__functions_pointers:
                #    size, bbs, name = self.__functions_pointers[value]
                #    field.name = 'func_ptr_%s_%d' % (name, field.offset)
                continue
            tgt = None
            try:
                # get enclosing structure @throws KeyError
                tgt = ctx.get_record_at_address(value)
            # there is no child structure member at pointed value.
            except (IndexError, ValueError) as e:
                log.debug('there is no child structure enclosing pointed value %0.8x - %s', value, e)
                field.set_pointee_desc('MemoryHandler management space')
                field.set_pointee_ctype('void')
                field.name = 'ptr_void_%d' % field.offset
                continue
            # structure found
            ## log.debug('Looking at child id:0x%x str:%s', tgt.address, tgt.to_string())
            # we always point on structure, not field
            field.set_pointee_addr(tgt.address)
            offset = value - tgt.address
            try:
                tgt_field = tgt.get_field_at_offset(offset)  # @throws IndexError
            except IndexError as e:
                # there is no field right there
                log.debug('there is no field at pointed value %0.8x. May need splitting byte field - %s', value, e)
                field.set_pointee_desc('Badly reversed field')
                field.set_pointee_ctype('void')
                field.name = 'ptr_void_%d' % field.offset
                continue
            # do not put exception for field 0. structure name should appears
            # anyway.
            field.set_pointee_desc('%s.%s' % (tgt.name, tgt_field.name))
            # TODO:
            # do not complexify code by handling target field type,
            # lets start with simple structure type pointer,
            # later we would need to use tgt_field.ctypes depending on field
            # offset
            field.set_pointee_ctype(tgt.name)
            # field.name = '%s_%s_%d' % (tgt.name, tgt_field.name, field.offset)
            field.name = 'ptr_%s_%d' % (tgt.name, field.offset)
            # all

        _record.set_reverse_level(self._reverse_level)
        return
