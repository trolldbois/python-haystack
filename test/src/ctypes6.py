# -*- coding: utf-8 -*-

from haystack import listmodel

class CTypes6Validator(listmodel.ListModel):

    def __init__(self, memory_handler, my_constraints, my_module):
        super(CTypes6Validator, self).__init__(memory_handler, my_constraints)
        self.ctypes6 = my_module
        # double linked list management structure type
        self.register_double_linked_list_record_type(self.ctypes6.struct_entry, 'flink', 'blink')
        # heads
        if self._target.get_word_size() == 4:
            self.register_double_linked_list_field_and_type(self.ctypes6.struct_Node, 'list', self.ctypes6.struct_Node, 'list')
        elif self._target.get_word_size() == 8:
            self.register_double_linked_list_field_and_type(self.ctypes6.struct_Node, 'list', self.ctypes6.struct_Node, 'list')

