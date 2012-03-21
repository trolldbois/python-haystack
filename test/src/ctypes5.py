
import sys

from haystack import model
from haystack import listmodel
from ctypes import *

STRING = c_char_p


class entry(Structure):
    pass
Entry = entry
entry._fields_ = [
    ('flink', POINTER(Entry)),
    ('blink', POINTER(Entry)),
]
class usual(Structure):
    pass
usual._fields_ = [
    ('val1', c_uint),
    ('val2', c_uint),
    ('root', Entry),
    ('val2b', c_uint),
    ('val1b', c_uint),
]
class Node(Structure):
    pass
Node._fields_ = [
    ('val1', c_uint),
    ('list', Entry),
    ('val2', c_uint),
]

usual._listHead_ = [  ('root', Node, 'list'),]
Node._listMember_ = ['list']

listmodel.declare_double_linked_list_type(Entry, 'flink', 'blink')



model.registerModule(sys.modules[__name__])


