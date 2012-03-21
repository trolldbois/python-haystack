#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
""" Win 7 heap structure - from LGPL metasm"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"


''' insure ctypes basic types are subverted '''
from haystack import model
from haystack.config import Config

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

from haystack.reverse.win32 import win7heap_generated as gen

import ctypes
import struct
import logging, sys

log=logging.getLogger('win7heap')

# ============== Internal type defs ==============

################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################





############# Start expectedValues and methods overrides #################

## fix partial declaration
_HEAP_LOCK._fields_ = [
  ('voidme', ctypes.c_ubyte),
  ]


## HEAP_SEGMENT

_HEAP_SEGMENT.expectedValued = {
  'SegmentSignature':[0xffeeffee],
}

#_HEAP_SEGMENT.UCRSegmentList. points to _HEAP_UCR_DESCRIPTOR.SegmentEntry.
#_HEAP_UCR_DESCRIPTOR.SegmentEntry. points to _HEAP_SEGMENT.UCRSegmentList.

_HEAP_SEGMENT._listHead_ = [  ('UCRSegmentList', _HEAP_UCR_DESCRIPTOR, 'ListEntry', -8),]
##_HEAP_SEGMENT._listHead_ = [  ('UCRSegmentList', _HEAP_UCR_DESCRIPTOR, 'SegmentEntry'),]
#_HEAP_SEGMENT._listMember_ = ['SegmentListEntry']



###### HEAP

_HEAP.expectedValues = {
  'Signature':[0xeeffeeff],
}
_HEAP._listHead_ = [  ('SegmentList', _HEAP_SEGMENT, 'SegmentListEntry', -16 ),]
#HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
#SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
# you need to ignore the Head in the iterator...

#### HEAP_UCR_DESCRIPTOR
#_HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
#_HEAP_UCR_DESCRIPTOR._listHead_ = [  ('SegmentEntry', _HEAP_SEGMENT, 'SegmentListEntry'),  ]

########## _LIST_ENTRY
from haystack import listmodel
listmodel.declare_double_linked_list_type(_LIST_ENTRY, 'FLink', 'BLink')









