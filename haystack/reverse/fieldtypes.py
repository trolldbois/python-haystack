#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import ctypes

from haystack.reverse import config
from haystack.reverse import structure


"""
the Python classes to represent the guesswork record and field typing of
allocations.
"""


log = logging.getLogger('field')

# Field related functions and classes


class FieldType(object):
    """
    Represents the type of a field.
    """
    types = set()

    def __init__(self, _id, basename, typename, sig, isPtr=False):
        self._id = _id
        self.basename = basename
        self.ctypes = typename
        self.sig = sig
        self.isPtr = isPtr

    @classmethod
    def makePOINTER(cls, typ):
        if typ == STRING:
            return STRING_POINTER
        return cls(typ._id + 0xa, typ.basename + '_ptr', 'ctypes.POINTER(%s)' % (typ.ctypes), 'P', True)

    def __cmp__(self, other):
        try:
            return cmp(self._id, other._id)
        except AttributeError as e:
            return -1

    def __hash__(self):
        return hash(self._id)

    def __str__(self):
        return '<FieldType %s>' % self.basename

    def __repr__(self):
        return '<t:%s>' % self.basename


class FieldTypeStruct(FieldType):
    """
    Fields that are know independent structure.
    In case we reverse a Big record that has members of known record types.
    """

    def __init__(self, typename):
        super(FieldTypeStruct, self).__init__(0x1, typename, typename, 'K', isPtr=False)

    def __str__(self):
        return self.basename


class FieldTypeArray(FieldType):
    """
    An array type
    """
    def __init__(self, basicTypeName):
        super(FieldTypeArray, self).__init__(self, 0x60, 'array_%s' % basicTypeName, 'a', isPtr=False)


# setup all the know types that are interesting to us
UNKNOWN = FieldType(0x0, 'untyped', 'ctypes.c_ubyte', 'u')
STRUCT = FieldType(0x1, 'struct', 'Structure', 'K')
ZEROES = FieldType(0x2, 'zerroes', 'ctypes.c_ubyte', 'z')
STRING = FieldType(0x4, 'text', 'ctypes.c_char', 'T')
STRING16 = FieldType(0x14, 'utf16', 'ctypes.c_char', 'T')
STRINGNULL = FieldType(0x6, 'text0', 'ctypes.c_char', 'T')
STRING_POINTER = FieldType(0x4 + 0xa, 'text_ptr', 'ctypes.c_char_p', 's', True)
INTEGER = FieldType(0x18, 'int', 'ctypes.c_uint', 'I')
SMALLINT = FieldType(0x8, 'small_int', 'ctypes.c_uint', 'i')
SIGNED_SMALLINT = FieldType(0x28, 'signed_small_int', 'ctypes.c_int', 'i')
ARRAY = FieldType(0x40, 'array', 'Array', 'a')
BYTEARRAY = FieldType(0x50, 'array', 'ctypes.c_ubyte', 'a')
# ARRAY_CHAR_P = FieldType(0x9, 'array_char_p',     'ctypes.c_char_p',   'Sp')
POINTER = FieldType(0xa, 'ptr', 'ctypes.c_void_p', 'P', True)
PADDING = FieldType(0xff, 'pad', 'ctypes.c_ubyte', 'X')


class Field(object):
    """
    Class that represent a Field instance, a FieldType instance.
    """
    def __init__(self, offset, _type, size, is_padding):
        self.offset = offset
        self.size = size
        # mhh not sure. what about array ?
        assert isinstance(_type, FieldType)
        self.typename = _type
        self._ctype = None
        self.padding = is_padding
        self.typesTested = []
        self.value = None
        self.comment = ''
        self.usercomment = ''
        self.encoding = None
        self.decoded = True
        self._uncertainty = None

    def setComment(self, txt):
        self.usercomment = '# %s' % txt

    def getComment(self):
        return self.usercomment

    def is_string(self):  # null terminated
        return self.typename in [STRING, STRING16, STRINGNULL, STRING_POINTER]

    def is_pointer(self):
        return issubclass(self.__class__, PointerField)

    def is_zeroes(self):
        return self.typename == ZEROES

    def is_array(self):  # will be overloaded
        return self.typename == ARRAY or self.typename == BYTEARRAY

    def is_integer(self):
        return self.typename == INTEGER or self.typename == SMALLINT or self.typename == SIGNED_SMALLINT

    def is_record(self):
        return self.typename == STRUCT

    def is_pointer_to_string(self):
        # pointer is Resolved
        if not self.is_pointer():
            return False
        if hasattr(self, '_ptr_to_ext_lib'):
            return False
        return self.get_pointee().is_string()

    def set_ctype(self, name):
        self._ctype = name

    def get_ctype(self):
        if self._ctype is None:
            return self.typename._ctype
        return self._ctype
        # FIXME TODO

    def get_typename(self):
        if self.is_string() or self.is_zeroes():
            return '%s * %d' % (self.typename.ctypes, len(self))
        elif self.is_array():
            # TODO should be in type
            return '%s * %d' % (self.typename.ctypes,
                                len(self) / self.element_size)
        elif self.is_record():
            return '%s' % self.typename
        elif self.typename == UNKNOWN:
            return '%s * %d' % (self.typename.ctypes, len(self))
        return self.typename.ctypes

    def set_name(self, name):
        self.name = name

    def get_name(self):
        if hasattr(self, 'name'):
            return self.name
        else:
            return '%s_%s' % (self.typename.basename, self.offset)

    def set_uncertainty(self, desc=None):
        self._uncertainty = True
        self._uncertainty_desc = desc

    def __hash__(self):
        return hash((self.offset, self.size, self.typename))

    # def tuple(self):
    #  return (self.offset, self.size, self.typename)

    def __cmp__(self, other):
        # XXX : Perf... cmp sux
        try:
            if self.offset < other.offset:
                return -1
            elif self.offset > other.offset:
                return 1
            elif (self.offset, self.size, self.typename) == (other.offset, other.size, other.typename):
                return 0
            # last chance, expensive cmp
            return cmp((self.offset, self.size, self.typename),
                       (other.offset, other.size, other.typename))
        except AttributeError as e:
            # if not isinstance(other, Field):
            return -1

    def __len__(self):
        return int(self.size)  # some long come and goes

    def __repr__(self):
        return str(self)

    def __str__(self):
        return '<Field offset:%d size:%s t:%s>' % (self.offset, self.size, self.typename)

    def get_value(self, _record, maxLen=120):
        bytes = self._get_value(_record, maxLen)
        if isinstance(bytes, str):
            bl = len(str(bytes))
            if bl >= maxLen:
                bytes = bytes[:maxLen / 2] + '...' + \
                    bytes[-(maxLen / 2):]  # idlike to see the end
        return bytes

    def _get_value(self, _record, maxLen=120):
        word_size = _record._target.get_word_size()
        if len(self) == 0:
            return '<-haystack no pattern found->'
        if self.is_string():
            if self.typename == STRING16:
                try:
                    my_bytes = "%s" % (repr(_record.bytes[self.offset:self.offset + self.size].decode('utf-16')))
                except UnicodeDecodeError as e:
                    log.error('ERROR ON : %s', repr(_record.bytes[self.offset:self.offset + self.size]))
                    my_bytes = _record.bytes[self.offset:self.offset + self.size]
            else:
                my_bytes = "'%s'" % (_record.bytes[self.offset:self.offset + self.size])
        elif self.is_integer():
            # what about endianness ?
            endianess = '<' # FIXME dsa self.endianess
            data = _record.bytes[self.offset:self.offset + word_size]
            val = _record._target.get_target_ctypes_utils().unpackWord(data, endianess)
            return val
        elif self.is_zeroes():
            my_bytes = repr('\\x00'*len(self))
        elif self.is_array():
            log.warning('ARRAY in Field type, %s', self.typename)
            log.error('error in 0x%x offset 0x%x', _record.address, self.offset)
            my_bytes = ''.join(['[', ','.join([el.to_string(_record) for el in self.elements]), ']'])
        elif self.padding or self.typename == UNKNOWN:
            my_bytes = _record.bytes[self.offset:self.offset + len(self)]
        elif self.is_pointer():
            data = _record.bytes[self.offset:self.offset + word_size]
            if len(data) != word_size:
                print repr(data), len(data)
                import pdb
                pdb.set_trace()
            val = _record._target.get_target_ctypes_utils().unpackWord(data)
            return val
        else:  # bytearray, pointer...
            my_bytes = _record.bytes[self.offset:self.offset + len(self)]
        return my_bytes

    def get_signature(self):
        return (self.typename, self.size)

    def to_string(self, _record, prefix=''):
        # log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
        #    %(self.isPointer(), self.isInteger(), self.isZeroes(), self.padding, self.typename.basename) )
        value = self.get_value(_record, config.commentMaxSize)
        if self.is_pointer():
            comment = '# @ 0x%0.8x %s %s' % (value, self.comment, self.usercomment)
        elif self.is_integer():
            comment = '#  0x%x %s %s' % (value, self.comment, self.usercomment)
        elif self.is_zeroes():
            comment = '''# %s %s zeroes: '\\x00'*%d''' % (
                self.comment, self.usercomment, len(self))
        elif self.is_string():
            comment = '#  %s %s %s: %s' % (self.comment,
                                           self.usercomment,
                                           self.typename.basename,
                                           self.get_value(_record, config.commentMaxSize))
        elif self.is_record():
            comment = '#'
        else:
            # unknown
            comment = '# %s %s else bytes:%s' % (
                self.comment, self.usercomment, repr(self.get_value(_record, config.commentMaxSize)))

        fstr = "%s( '%s' , %s ), %s\n" % (prefix, self.get_name(), self.get_typename(), comment)
        return fstr

    def __getstate__(self):
        d = self.__dict__.copy()
        # print d.keys()
        # print d

        return d


class PointerField(Field):
    """
    represent a pointer field
    """
    def __init__(self, offset, size):
        super(PointerField, self).__init__(offset, POINTER, size, False)
        self._pointee = None

    def set_pointee(self, pointee_field):
        self._pointee = pointee_field

    def get_pointee(self):
        return self._pointee

    def set_child_ctype(self, name):
        #self.set_ctype('ctypes.POINTER(%s)' % name)
        #self.set_ctype('ctypes.POINTER(%s)' % name.__name__)
        # print self.get_ctype()
        # 2015-09-13
        # FIXME should probably use a memory_handler
        # this breaks pickling
        self.set_ctype(ctypes.POINTER(name))

    # def get_ctype(self):
    #    return eval(Field.get_ctype(self))

    # FIXME, probably need a setstate
    def __getstate__(self):
        d = self.__dict__.copy()
        d['_ctype'] = str(d['_ctype'])

        return d

    def set_child_addr(self, addr):
        self._child_addr = addr

    def set_child_desc(self, desc):
        self._child_desc = desc


class ArrayField(Field):
    """
    Represents an array field.
    """
    # , basicTypename, basicTypeSize ): # use first element to get that info
    def __init__(self, elements):
        self.offset = elements[0].offset
        self.typename = FieldTypeArray(elements[0].typename.basename)

        self.elements = elements
        self.nbElements = len(elements)
        self.basicTypeSize = len(elements[0])
        self.basicTypename = elements[0].typename

        self.size = self.basicTypeSize * len(self.elements)

        super(ArrayField, self).__init__(self.offset, self.typename, self.size, False)

        self.padding = False
        self.value = None
        self.comment = ''
        self.usercomment = ''
        self.decoded = True

    def is_array(self):
        return True

    def get_ctype(self):
        return self._ctype

    def get_typename(self):
        return '%s * %d' % (self.basicTypename.ctypes, self.nbElements)

    def _get_value(self, _record, maxLen=120):
        # show number of elements and elements types
        bytes = '%d x ' % (len(
            self.elements)) + ''.join(['[', ','.join([el.to_string('') for el in self.elements]), ']'])
        # thats for structFields
        #bytes= '%d x '%(len(self.elements)) + ''.join(['[',','.join([el.typename for el in el0.typename.elements]),']'])
        return bytes

    def to_string(self, _record, prefix=''):
        log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
                  % (self.is_pointer(), self.is_integer(), self.is_zeroes(), self.padding, self.typename.basename))
        #
        comment = '# %s %s array:%s' % (
            self.comment, self.usercomment, self.get_value(_record, config.commentMaxSize))
        fstr = "%s( '%s' , %s ), %s\n" % (
            prefix, self.get_name(), self.get_typename(), comment)
        return fstr


class RecordField(Field, structure.AnonymousRecord):
    """
    make a record field
    """
    def __init__(self, parent, offset, field_name, typename, fields):
        size = sum([len(f) for f in fields])
        _address = parent.address + offset
        structure.AnonymousRecord.__init__(self, parent._memory_handler, _address, size, prefix=None)
        Field.__init__(self, offset, FieldTypeStruct(typename), size, False)
        self.set_name(field_name)
        self.add_fields(fields)
        return

#    def to_string(self, *args):
#        # print self.fields
#        fieldsString = '[ \n%s ]' % (''.join([field.to_string(self, '\t') for field in self.get_fields()]))
#        info = 'rlevel:%d SIG:%s size:%d' % (self.get_reverse_level(), self.get_signature(), len(self))
#        ctypes_def = '''
#class %s(ctypes.Structure):  # %s
#  _fields_ = %s
#
#''' % (self.get_name(), info, fieldsString)
#        return ctypes_def
