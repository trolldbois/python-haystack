# -*- coding: utf-8 -*-

from haystack.constraints import NotNull


def populate(target):
    # FIXME : put in constraints file.
    # classes copy from ctypes6_genXX is done from unittest setUp

    # x32 -4.
    #import ctypes
    if target.get_word_size() == 4:
        struct_Node._listHead_ = [('list', struct_Node, 'XXXX', -4),]
    elif target.get_word_size() == 8:
        struct_Node._listHead_ = [('list', struct_Node, 'XXXX', -8),]
    #                           #('list', struct_Node, 'qwd', -4)]
    from haystack import listmodel
    listmodel.declare_double_linked_list_type(target.get_target_ctypes(), struct_entry, 'flink', 'blink')
