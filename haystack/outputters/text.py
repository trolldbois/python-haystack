#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This class produce a textual output.

"""

import logging

from haystack.outputters import Outputter
from haystack import basicmodel


log = logging.getLogger('text')


class RecursiveTextOutputter(Outputter):

    """
    TODO:
    make a recursive parser that create a text representation of a ctypes
    structure.
    Returned string should be python compatible ( dict )
    """

    def parse(self, obj, prefix='', depth=10):
        """ Returns a string formatted description of this Structure.
        The returned string should be python-compatible...
        """
        # TODO: use a ref table to stop loops on parsed instance,
        #             depth kinda sux.
        if depth <= 0:
            return 'None, # DEPTH LIMIT REACHED'
        if hasattr(obj, 'toString'):
            return obj.toString(prefix, depth)
        if hasattr(obj, '_orig_address_'):
            s = "{ # <%s at 0x%x>" % (
                obj.__class__.__name__, obj._orig_address_)
        else:
            s = "{ # <%s at 0x???>" % (obj.__class__.__name__)
        for field, typ in basicmodel.get_fields(obj):
            attr = getattr(obj, field)
            s += '\n%s"%s": %s' % (prefix,
                                   field,
                                   self._attrToString(
                                       attr,
                                       field,
                                       typ,
                                       prefix,
                                       depth))
        s += '\n' + prefix + '}'
        return s

    def _attrToString(self, attr, field, attrtype, prefix, depth=-1):
        """This should produce strings, based on self._ctypes structures. No pyOBJ"""
        s = ''
        if self._ctypes.is_basic_type(attrtype):
            if self._ctypes.is_basic_ctype(type(attr)):
                value = attr.value
            else:
                value = repr(attr)
            s = '%s, # %s' % (value, attrtype.__name__)
            if attr is None:
                raise ValueError('This field %s has not been loaded' % (field))
            # print a nice hex output on int types
            try:
                s += ' ' + hex(value)
            except TypeError as e:
                pass
        elif self._ctypes.is_struct_type(attrtype) or self._ctypes.is_union_type(attrtype):
            s = '%s,' % (self.parse(attr, prefix + '\t', depth - 1))
        elif self._ctypes.is_function_type(attrtype):
            # only print address in target space
            myaddress = self._utils.get_pointee_address(attr)
            myaddress_fmt = self._utils.formatAddress(myaddress)
            s = '%s, #(FIELD NOT LOADED: function type)' % (myaddress_fmt)
        elif self._ctypes.is_array_of_basic_type(attrtype):
            # array of int, float, char...
            s = '%s,' % (repr(self._utils.ctypes_to_python_array(attr)))
        elif self._ctypes.is_array_type(attrtype):
            # array of something else than int/byte
            # go through each elements, we hardly can make a array out of that.
            s = '['
            _attrType = self._utils.get_subtype(attrtype)
            # eltyp = type(attr[0])
            for i in range(0, len(attr)):
                s += '\n%s%s' % (prefix + '\t',
                                 self._attrToString(
                                     attr[i],
                                     i,
                                     _attrType,
                                     prefix,
                                     depth - 1))
            s += '\n%s],' % (prefix + '\t')
        elif self._ctypes.is_cstring_type(attrtype):
            if not bool(attr.ptr):
                return "<NULLPTR>"
            if self._memory_handler.hasRef(
                    self._ctypes.CString, self._utils.get_pointee_address(attr.ptr)):
                s = self._memory_handler.getRef(
                    self._ctypes.CString,
                    self._utils.get_pointee_address(
                        attr.ptr))
            else:
                raise Exception('This CString was not in cache')
            s = '"%s" , #(CString)' % (s)
        elif self._ctypes.is_pointer_type(attrtype):
            myaddress = self._utils.get_pointee_address(attr)
            myaddress_fmt = self._utils.formatAddress(myaddress)
            _attrType = self._utils.get_subtype(attrtype)
            contents = self._memory_handler.getRef(_attrType, myaddress)
            # TODO: can I just dump this block into a recursive call ?
            # probably not if we want to stop LIST types from recursing
            # FIXME why contents is None ?
            #if field == 'ProcessHeaps':
            #    import code
            #    code.interact(local=locals())
            if myaddress == 0 or contents is None: # FIXME the solution is probably to remove the content test here
                # only print address/null
                s = '%s,' % (myaddress_fmt)
            elif self._ctypes.is_pointer_to_void_type(attrtype):
                # c_void_p, c_char_p, can load target
                s = '%s, #(FIELD NOT LOADED: void pointer)' % myaddress_fmt # self._utils.formatAddress(attr.value)
            elif isinstance(self, type(contents)):
                # pointer of self type ? lists ?
                # TODO: decide if we recurse in lists or not.
                # if we do, comment this elif/block
                s = '{ #(%s) LIST of %s\n%s},' % (
                    myaddress_fmt, _attrType.__name__, prefix + '\t')
            # TODO CUT HERE
            elif (self._ctypes.is_pointer_to_struct_type(attrtype)
                  or self._ctypes.is_pointer_to_union_type(attrtype)):
                s = '%s,' % (self.parse(contents, prefix + '\t', depth - 1))
            # FIXME: get coherent with python or just use the one python and then a python to string.
            else:
                # FIXME we should NOT recurse
                # could be a pointer to basic type, array type, pointer, ...
                # we recurse.
                # s = prefix + '"%s": #(%s)\n%s,'%(field, myaddress_fmt,
                # self._attrToString(contents, '', _attrType, prefix+'\t'))
                s = "%s," % self._attrToString(
                    contents,
                    field,
                    _attrType,
                    prefix + '\t',
                    depth - 1)
                #raise NotImplementedError('what is this %s'%(_attrType))
        else:  # wtf ?
            s = '%s, # Unknown/bug DEFAULT repr' % (repr(attr))
        return s
