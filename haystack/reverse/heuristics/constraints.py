# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
"""

from haystack.reverse import structure

from collections import Counter
import logging

log = logging.getLogger('constraints')


class ConstraintsReverser(object):
    def __init__(self, memory_handler):
        self.__memory_handler = memory_handler
        self.__process_context = memory_handler.get_reverse_context()

    def activate(self, _record_type, members):
        # apply the fields template to all members of the list
        for list_item_addr in members:
            _context = self.__process_context.get_context_for_address(list_item_addr)
            _item = _context.get_record_for_address(list_item_addr)
            _item.set_record_type(_record_type, True)

        # push the LIST_ENTRY type into the context/memory_handler
        self.__process_context.add_reversed_type(_record_type, members)

        return

    def verify(self, _record_type, members):
        records = []
        lines = []
        # try to apply the fields template to all members of the list
        for list_item_addr in members:
            _context = self.__process_context.get_context_for_address(list_item_addr)
            _item = _context.get_record_for_address(list_item_addr)
            new_record = structure.AnonymousRecord(self.__memory_handler, _item.address, len(_item), prefix=None)
            new_record.set_record_type(_record_type, True)
            records.append(new_record)
        lines.append('# instances: [%s]' % (','.join(['0x%x' % addr for addr in members])))

        # check fields values
        for i, field in enumerate(_record_type.get_fields()):
            if field.is_record():
                # we ignore the subrecord. is too complicated to show.
                continue
            values = []
            for _item in records:
                val = _item.get_value_for_field(field)
                if field.is_pointer():
                    values.append(hex(val))
                else:
                    values.append(val)
            if field.is_zeroes() and len(values) == 1:
                values = [0]
                # ignore the field in that case.
                continue
            counter = Counter(values)
            # print 'field: %s values: %s' % (field.name, counter)
            lines.append('# field: %s values: %s' % (field.name, counter))
        return lines
