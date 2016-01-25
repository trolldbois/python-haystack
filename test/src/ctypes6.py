# -*- coding: utf-8 -*-

from haystack import listmodel
from haystack.abc import interfaces


class CTypes6Validator(listmodel.ListModel):
    def __init__(self, memory_handler, my_constraints, my_module):
        super(CTypes6Validator, self).__init__(memory_handler, my_constraints)
        self.ctypes6 = my_module
        # double linked list management structure type
        self.register_single_linked_list_record_type(self.ctypes6.struct_slist, 'next')
        self.register_double_linked_list_record_type(self.ctypes6.struct_entry, 'flink', 'blink')
        # heads
        self.register_linked_list_field_and_type(self.ctypes6.struct_usual, 'root', self.ctypes6.struct_Node, 'list')
        self.register_linked_list_field_and_type(self.ctypes6.struct_Node, 'list', self.ctypes6.struct_Node, 'list')
        self.register_linked_list_field_and_type(self.ctypes6.struct_single_node, 'entry', self.ctypes6.struct_single_node, 'entry')


class NodeDynamicValidator(interfaces.IRecordTypeDynamicConstraintsValidator):
    def is_valid(self, _record):
        if _record.val1 != 0xdeadbeef:
            return False
        if _record.val2 != 0xffffffff:
            return False
        return True


class EntryDynamicValidator(interfaces.IRecordTypeDynamicConstraintsValidator):
    """Only validates head and tail"""
    def __init__(self, memory_handler):
        self.memory_handler = memory_handler
        self.ctypes_utils = memory_handler.get_target_platform().get_target_ctypes_utils()

    def is_valid(self, _record):
        flink = self.ctypes_utils.get_pointee_address(_record.flink)
        blink = self.ctypes_utils.get_pointee_address(_record.blink)
        if flink == 0 and blink != 0:
            # head elements
            return True
        if blink == 0 and flink != 0:
            # tail elements
            return True
        return False
