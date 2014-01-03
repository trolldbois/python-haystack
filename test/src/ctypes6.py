# -*- coding: utf-8 -*-

from haystack import model
from haystack.constraints import RangeValue,NotNull,IgnoreMember

def populate():
    # classes copy from ctypes6_genXX is done from unittest setUp
    struct_usual.expectedValues={
                "val1": [0x0aaaaaaa],
                "val2": [0x0ffffff0],
                "txt": [NotNull] # text there
                }

    struct_Node.expectedValues={
                "val1": [0xdeadbeef,0xdeadbabe],
                "val2": [0xffffffff],
                #"list.flink": [0,NotNull],
                #"list.blink": [0,NotNull],
                }
    struct_entry.expectedValues={
                #"flink": [0,NotNull],
                #"blink": [0,NotNull],
                }
    
    # x32 -4.
    import ctypes
    struct_Node._listHead_ = [('list', struct_Node, 'wqd', -4),]
                               #('list', struct_Node, 'qwd', -4)]
    from haystack import listmodel
    listmodel.declare_double_linked_list_type(struct_entry, 'flink', 'blink')


