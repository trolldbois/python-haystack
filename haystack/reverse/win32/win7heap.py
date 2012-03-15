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

import ctypes
import logging, sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

from haystack.reverse.win32 import win7heap_generated as gen

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

############ 

_HEAP_SEGMENT.expectedValued = {
  'SegmentSignature':[0xffeeffee],
}

_HEAP.expectedValues = {
    'Signature':[0xeeffeeff],
    }

#def BIGNUM_loadMembers(self, mappings, maxDepth):
#  ''' 
#  if not self.isValid(mappings):
#    log.debug('BigNUm tries to load members when its not validated')
#    return False
#  # Load and memcopy d / BN_ULONG *
# attr_obj_address=getaddress(self.d)
#  if not bool(self.d):
#    log.debug('BIGNUM has a Null pointer d')
#    return True
#  memoryMap = is_valid_address_value( attr_obj_address, mappings)
#  contents=(BN_ULONG*self.top).from_buffer_copy(memoryMap.readArray(attr_obj_address, BN_ULONG, self.top))
#  log.debug('contents acquired %d'%ctypes.sizeof(contents))
#  self.d.contents=BN_ULONG.from_address(ctypes.addressof(contents))
#  self.d=ctypes.cast(contents, ctypes.POINTER(BN_ULONG) ) 
 # return True

#def BIGNUM_isValid(self,mappings):
#  if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
#    return False
#  return LoadableMembers.isValid(self,mappings)

#BIGNUM.loadMembers = BIGNUM_loadMembers
#BIGNUM.isValid     = BIGNUM_isValid
#BIGNUM.__str__     = BIGNUM___str__
#################


