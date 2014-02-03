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

"""ensure ctypes basic types are subverted"""
from haystack import model
from haystack import utils
from haystack import constraints

from haystack.structures.win32 import winheap_generated as gen

import ctypes
import struct
import logging
import sys

import code

log = logging.getLogger('winheap')

################ START copy generated classes ##########################
# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])
# register all classes to haystack
# create plain old python object from ctypes.Structure's, to pickle them
model.registerModule(sys.modules[__name__])
################ END copy generated classes ############################


############# Start expectedValues and methods overrides #################


HEAP_SEGMENT.expectedValued = {
  'SegmentSignature':[0xffeeffee],
}

HEAP.expectedValues = {
    'Signature':[0xeeffeeff],
    }


#################


