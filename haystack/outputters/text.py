#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This class produce a textual output.

"""

import logging
import numbers
import sys

from haystack import utils
from haystack import constraints
from haystack.utils import get_subtype

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2014 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('text')

class RecursiveTextOutputter(object): 
    """ 
    TODO:
    make a recursive parser that create a text representation of a ctypes
    structure.
    Returned string should be python compatible ( dict )
    """
    def __init__(self, mappings):
        self.mappings = mappings
    
    
    def parse(self, obj, prefix='', depth=5): 
        """ Returns a string formatted description of this Structure. 
        The returned string should be python-compatible...
        """
        # TODO: use a ref table to stop loops on parsed instance, 
        #             depth kinda sux.
        if depth == 0 :
            return 'None, # DEPTH LIMIT REACHED'
        if hasattr(obj, '_orig_address_'):
            s="{ # <%s at @%x>"%(obj.__class__.__name__, obj._orig_address_)
        else:
            s="{ # <%s at @???>"%(obj.__class__.__name__)
        for field,typ in obj.getFields():
            attr = getattr(obj,field)
            s += '\n'
            s += self._attrToString(attr, field, typ, prefix, depth)
        s += '\n'+prefix+'}'
        return s
        
    def _attrToString(self, attr, field, attrtype, prefix, depth=-1):
        """This should produce strings, based on ctypes structures. No pyOBJ"""
        ctypes = self.mappings.config.ctypes
        s=''
        if ctypes.is_basic_type(attrtype): 
            if ctypes.is_basic_ctype(type(attr)):
                value = attr.value
            else:
                value = repr(attr)
            s = prefix+'"%s": %s, # %s'%(field, value, attrtype.__name__)
            if attr is None:
                raise ValueError('This field %s has not been loaded'%(field))
            # print a nice hex output on int types
            try:
                s += ' ' + hex(value)
            except TypeError as e:
                pass
        elif ctypes.is_struct_type(attrtype) or ctypes.is_union_type(attrtype):
            s = prefix + '"%s": %s,'%(field,
                                 self.parse(attr, prefix+'\t', depth-1))
        elif ctypes.is_function_type(attrtype):
            # only print address in target space
            myaddress = utils.getaddress(attr)
            myaddress_fmt = utils.formatAddress(myaddress)
            s = prefix + '"%s": %s, #(FIELD NOT LOADED: function type)'%(
                                                           field, myaddress_fmt)
        elif ctypes.is_array_of_basic_type(attrtype):
            # array of int, float ...
            s = prefix + '"%s": b%s,'%(field, repr(utils.array2bytes(attr)))
        elif ctypes.is_array_type(attrtype):
            # array of something else than int/byte
            # go through each elements, we hardly can make a array out of that.
            s = prefix + '"%s" :{'%(field)
            eltyp = type(attr[0])
            for i in range(0,len(attr)):
                s += self._attrToString(attr[i], i, eltyp, '')
            s += '},'
        elif ctypes.is_pointer_type(attrtype):
            myaddress = utils.getaddress(attr)
            myaddress_fmt = utils.formatAddress(myaddress)
            _attrType = get_subtype(attrtype)                
            contents = self.mappings.getRef(_attrType, myaddress)
            # TODO: can I just dump this block into a recursive call ?
            # probably not if we want to stop LIST types from recursing
            # FIXME why contents is None ?
            if myaddress == 0 or contents is None:
                # only print address/null
                s = prefix + '"%s": %s,'%(field, myaddress_fmt) 
            elif ctypes.is_pointer_to_void_type(attrtype) :
                # c_void_p, c_char_p, can load target
                s = prefix + '"%s": %s, #(FIELD NOT LOADED: void pointer)'%(
                                                           field, myaddress_fmt)
            elif type(self) == type(contents):
                # pointer of self type ? lists ?
                # TODO: decide if we recurse in lists or not.
                # if we do, comment this elif/block
                s = prefix + '"%s": { #(%s) LIST of %s\n%s},'%(field, 
                                 myaddress_fmt, _attrType.__name__, prefix+'\t')
            # TODO CUT HERE
            elif (ctypes.is_pointer_to_struct_type(attrtype)
                  or ctypes.is_pointer_to_union_type(attrtype)):
                s = prefix + '"%s": %s,'%(field,
                                        self.parse(contents,prefix+'\t', depth-1))
            else:
                # could be a pointer to basic type, array type, pointer, ...
                # we recurse.
                s = prefix + '"%s": #(%s)\n%s,'%(field, myaddress_fmt, 
                       self._attrToString(contents, '', _attrType, prefix+'\t'))
                #raise NotImplementedError('what is this %s'%(_attrType))
        elif ctypes.is_cstring_type(attrtype):
            s = prefix + '"%s": "%s" , #(CString)'%(field, self.mappings.getRef(ctypes.CString, 
                                                    utils.getaddress(attr.ptr)))
        else: # wtf ? 
            s = prefix+'"%s": %s, # Unknown/bug DEFAULT repr'%(field, repr(attr))
        return s

class TextOutputter(object): 
    """ 
    TODO:
    make a iterative parser that create a text representation of a ctypes
    structure.
    Returned string should be python compatible ( dict )
    """
    def __init__(self, mappings):
        self.mappings = mappings
    
    
    def parse(self, obj, prefix='', depth=5): 
        """ Returns a string formatted description of this Structure. 
        The returned string should be python-compatible...
        """
        # TODO: use a ref table to stop loops on parsed instance, 
        #             depth kinda sux.
        if depth == 0 :
            return 'None, # DEPTH LIMIT REACHED'
        if hasattr(obj, '_orig_address_'):
            s="{ # <%s at @%x>"%(obj.__class__.__name__, obj._orig_address_)
        else:
            s="{ # <%s at @???>"%(obj.__class__.__name__)
        for field,typ in obj.getFields():
            attr = getattr(obj,field)
            s += '\n'
            s += self._attrToString(attr, field, typ, prefix, depth)
        s += '\n'+prefix+'}'
        return s
        
    def _attrToString(self, attr, field, attrtype, prefix, depth=-1):
        """This should produce strings, based on ctypes structures. No pyOBJ"""
        ctypes = self.mappings.config.ctypes
        s=''
        if ctypes.is_basic_type(attrtype): 
            if ctypes.is_basic_ctype(type(attr)):
                value = attr.value
            else:
                value = repr(attr)
            s = prefix+'"%s": %s, # %s'%(field, value, attrtype.__name__)
            if attr is None:
                raise ValueError('This field %s has not been loaded'%(field))
            # print a nice hex output on int types
            try:
                s += ' ' + hex(value)
            except TypeError as e:
                pass
        elif ctypes.is_struct_type(attrtype) or ctypes.is_union_type(attrtype):
            s = prefix + '"%s": %s,'%(field,
                                        self.parse(attr, prefix+'\t', depth-1))
        elif ctypes.is_function_type(attrtype):
            # only print address in target space
            myaddress = utils.getaddress(attr)
            myaddress_fmt = utils.formatAddress(myaddress)
            s = prefix + '"%s": %s, #(FIELD NOT LOADED: function type)'%(
                                                           field, myaddress_fmt)
        elif ctypes.is_array_of_basic_type(attrtype):
            # array of int, float ...
            s = prefix + '"%s": b%s,'%(field, repr(utils.array2bytes(attr)))
        elif ctypes.is_array_type(attrtype):
            # array of something else than int/byte
            # go through each elements, we hardly can make a array out of that.
            s = prefix + '"%s" :{'%(field)
            eltyp = type(attr[0])
            for i in range(0,len(attr)):
                s += self._attrToString(attr[i], i, eltyp, '')
            s += '},'
        elif ctypes.is_pointer_type(attrtype):
            myaddress = utils.getaddress(attr)
            myaddress_fmt = utils.formatAddress(myaddress)
            _attrType = get_subtype(attrtype)                
            contents = self.mappings.getRef(_attrType, myaddress)
            # TODO: can I just dump this block into a recursive call ?
            # probably not if we want to stop LIST types from recursing
            # FIXME why contents is None ?
            if myaddress == 0 or contents is None:
                # only print address/null
                s = prefix + '"%s": %s,'%(field, myaddress_fmt) 
            elif ctypes.is_pointer_to_void_type(attrtype) :
                # c_void_p, c_char_p, can load target
                s = prefix + '"%s": %s, #(FIELD NOT LOADED: void pointer)'%(
                                                           field, myaddress_fmt)
            elif type(self) == type(contents):
                # pointer of self type ? lists ?
                # TODO: decide if we recurse in lists or not.
                # if we do, comment this elif/block
                s = prefix + '"%s": { #(%s) LIST of %s\n%s},'%(field, 
                                 myaddress_fmt, _attrType.__name__, prefix+'\t')
            # TODO CUT HERE
            elif (ctypes.is_pointer_to_struct_type(attrtype)
                  or ctypes.is_pointer_to_union_type(attrtype)):
                s = prefix + '"%s": %s,'%(field,
                                        self.parse(contents, prefix+'\t', depth-1))
            else:
                # could be a pointer to basic type, array type, pointer, ...
                # we recurse.
                s = prefix + '"%s": #(%s)\n%s,'%(field, myaddress_fmt, 
                       self._attrToString(contents, '', _attrType, prefix+'\t'))
                #raise NotImplementedError('what is this %s'%(_attrType))
        elif ctypes.is_cstring_type(attrtype):
            s = prefix + '"%s": "%s" , #(CString)'%(field, self.mappings.getRef(ctypes.CString, 
                                                    utils.getaddress(attr.ptr)))
        else: # wtf ? 
            s = prefix+'"%s": %s, # Unknown/bug DEFAULT repr'%(field, repr(attr))
        return s


