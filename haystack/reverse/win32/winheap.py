#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
""" Win heap structure - from LGPL metasm
http://www.informit.com/articles/article.aspx?p=1081496

"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes
import logging, sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

from haystack.reverse.win32 import winheap_generated as gen

log=logging.getLogger('winheap')

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

## make a match

_HEAP_SEGMENT.expectedValued = {
  'SegmentSignature':[0xffeeffee],
}

_HEAP.expectedValues = {
    'Signature':[0xeeffeeff],
    }


#################


