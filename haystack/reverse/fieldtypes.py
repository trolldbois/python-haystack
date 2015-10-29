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

    def __init__(self, _id, _name, _signature):
        self.__id = _id
        self.__name = _name
        self.__sig = _signature

    @property
    def id(self):
        return self.__id

    @property
    def name(self):
        return self.__name

    @property
    def signature(self):
        return self.__sig

    def __cmp__(self, other):
        try:
            return cmp(self.id, other.id)
        except AttributeError as e:
            return -1

    def __hash__(self):
        return hash(self.id)

    def __str__(self):
        return '<FieldType %s>' % self.name

    def __repr__(self):
        return '<t:%s>' % self.name


class FieldTypeStruct(FieldType):
    """
    Fields that are know independent structure.
    In case we reverse a Big record that has members of known record types.
    """

    def __init__(self, _typename):
        assert isinstance(_typename, str)
        super(FieldTypeStruct, self).__init__(0x1, _typename, 'K')

    def __str__(self):
        return self.name


class FieldTypeArray(FieldType):
    """
    An array type
    """
    def __init__(self, item_type, item_size, nb_items):
        super(FieldTypeArray, self).__init__(0x60, '%s*%d' % (item_type.name, nb_items), 'a')
        self.nb_items = nb_items
        self.item_type = item_type
        self.item_size = item_size
        self.size = item_size*nb_items


class RecordTypePointer(FieldType):
    def __init__(self, _type):
        #if typ == STRING:
        #    return STRING_POINTER
        super(RecordTypePointer, self).__init__(_type.id + 0xa, 'ctypes.POINTER(%s)' % _type.name, 'P')


# setup all the know types that are interesting to us
UNKNOWN = FieldType(0x0, 'ctypes.c_ubyte', 'u')
STRUCT = FieldType(0x1, 'Structure', 'K')
ZEROES = FieldType(0x2, 'ctypes.c_ubyte', 'z')
STRING = FieldType(0x4, 'ctypes.c_char', 'T')
STRING16 = FieldType(0x14, 'ctypes.c_char', 'T')
STRINGNULL = FieldType(0x6, 'ctypes.c_char', 'T')
STRING_POINTER = FieldType(0x4 + 0xa, 'ctypes.c_char_p', 's')
INTEGER = FieldType(0x18, 'ctypes.c_uint', 'I')
SMALLINT = FieldType(0x8, 'ctypes.c_uint', 'i')
SIGNED_SMALLINT = FieldType(0x28, 'ctypes.c_int', 'i')
ARRAY = FieldType(0x40, 'Array', 'a')
BYTEARRAY = FieldType(0x50, 'ctypes.c_ubyte', 'a')
# ARRAY_CHAR_P = FieldType(0x9, 'array_char_p',     'ctypes.c_char_p',   'Sp')
POINTER = FieldType(0xa, 'ctypes.c_void_p', 'P')
PADDING = FieldType(0xff, 'ctypes.c_ubyte', 'X')


class Field(object):
    """
    Class that represent a Field instance, a FieldType instance.
    """
    def __init__(self, name, offset, _type, size, is_padding):
        self.__name = name
        self.__offset = offset
        assert isinstance(_type, FieldType)
        self.__field_type = _type
        self.__size = size
        self.__padding = is_padding
        self.__comment = '#'

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, _name):
        if _name is None:
            self.__name = '%s_%s' % (self.field_type.name, self.offset)
        else:
            self.__name = _name

    @property
    def offset(self):
        return self.__offset

    @property
    def field_type(self):
        return self.__field_type

    @property
    def size(self):
        return self.__size

    @property
    def padding(self):
        return self.__padding

    @property
    def comment(self):
        return self.__comment

    @comment.setter
    def comment(self, txt):
        self.__comment = '# %s' % txt

    def is_string(self):  # null terminated
        return self.field_type in [STRING, STRING16, STRINGNULL, STRING_POINTER]

    def is_pointer(self):
        # we could be a pointer or a pointer string
        return issubclass(self.__class__, PointerField)

    def is_zeroes(self):
        return self.field_type == ZEROES

    def is_array(self):  # will be overloaded
        return self.field_type == ARRAY or self.field_type == BYTEARRAY

    def is_integer(self):
        return self.field_type == INTEGER or self.field_type == SMALLINT or self.field_type == SIGNED_SMALLINT

    def is_record(self):
        return self.field_type == STRUCT

    def is_gap(self):
        return self.field_type == UNKNOWN

    def get_typename(self):
        if self.is_string() or self.is_zeroes():
            return '%s*%d' % (self.field_type.name, len(self))
        elif self.is_array():
            # TODO should be in type
            return '%s*%d' % (self.field_type.name, len(self) / self.nb_items)
        elif self.field_type == UNKNOWN:
            return '%s*%d' % (self.field_type.name, len(self))
        return self.field_type.name

    def __hash__(self):
        return hash((self.offset, self.size, self.field_type))

    def __cmp__(self, other):
        # XXX : Perf... cmp sux
        try:
            if self.offset < other.offset:
                return -1
            elif self.offset > other.offset:
                return 1
            elif (self.offset, self.size, self.field_type) == (other.offset, other.size, other.field_type):
                return 0
            # last chance, expensive cmp
            return cmp((self.offset, self.size, self.field_type),
                       (other.offset, other.size, other.field_type))
        except AttributeError as e:
            # if not isinstance(other, Field):
            return -1

    def __len__(self):
        return int(self.size)  # some long come and goes

    def __repr__(self):
        return str(self)

    def __str__(self):
        return '<Field offset:%d size:%s t:%s>' % (self.offset, self.size, self.field_type)

    def get_signature(self):
        return self.field_type, self.size

    def to_string(self, value):
        if value is None:
            value = 0
        if self.is_pointer():
            comment = '# @ 0x%0.8x %s' % (value, self.comment)
        elif self.is_integer():
            comment = '# 0x%x %s' % (value, self.comment)
        elif self.is_zeroes():
            comment = '''# %s zeroes: '\\x00'*%d''' % (self.comment, len(self))
        elif self.is_string():
            comment = '#  %s %s: %s' % (self.comment, self.field_type.name, value)
        elif self.is_record():
            comment = '#'
        else:
            # unknown
            comment = '# %s else bytes:%s' % (self.comment, repr(value))
        # prep the string
        fstr = "( '%s' , %s ), %s\n" % (self.name, self.get_typename(), comment)
        return fstr


class PointerField(Field):
    """
    represent a pointer field
    """
    def __init__(self, name, offset, size):
        super(PointerField, self).__init__(name, offset, POINTER, size, False)
        self.__pointee = None
        self.__pointer_to_ext_lib = False\
        # ??
        self._child_addr = 0
        self._child_desc = None
        self._child_type = None

    @property
    def pointee(self):
        return self.__pointee

    @pointee.setter
    def pointee(self, pointee_field):
        self.__pointee = pointee_field

    def is_pointer_to_string(self):
        # if hasattr(self, '_ptr_to_ext_lib'):
        #    return False
        return self.pointee.is_string()

    def is_pointer_to_ext_lib(self):
        return self.__pointer_to_ext_lib

    def set_pointer_to_ext_lib(self):
        self.__pointer_to_ext_lib = True

    def set_pointee_addr(self, addr):
        self._child_addr = addr

    def set_pointee_desc(self, desc):
        self._child_desc = desc

    def set_pointee_ctype(self, _type):
        self._child_type = _type


class ArrayField(Field):
    """
    Represents an array field.
    """
    # , basicTypename, basicTypeSize ): # use first element to get that info
    def __init__(self, name, offset, item_type, item_size, nb_item):
        size = item_size * nb_item
        super(ArrayField, self).__init__(name, offset, FieldTypeArray(item_type, item_size, nb_item), size, False)

    def get_typename(self):
        return self.field_type.name

    def is_array(self):
        return True

    def _get_value(self, _record, maxLen=120):
        return None

    def to_string(self, _record, prefix=''):
        item_type = self.field_type.item_type
        # log.debug('P:%s I:%s Z:%s typ:%s' % (item_type.is_pointer(), item_type.is_integer(), item_type.is_zeroes(), item_type.name))
        log.debug("array type: %s", item_type.name)
        #
        comment = '# %s array' % self.comment
        fstr = "%s( '%s' , %s ), %s\n" % (prefix, self.name, self.get_typename(), comment)
        return fstr


class ZeroField(ArrayField):
    """
    Represents an array field of zeroes.
    """
    def __init__(self, name, offset, nb_item):
        super(ZeroField, self).__init__(name, offset, ZEROES, 1, nb_item)

    def is_zeroes(self):
        return True


class RecordField(Field, structure.AnonymousRecord):
    """
    make a record field
    """
    def __init__(self, parent, offset, field_name, field_type, fields):
        size = sum([len(f) for f in fields])
        _address = parent.address + offset
        structure.AnonymousRecord.__init__(self, parent._memory_handler, _address, size, prefix=None)
        Field.__init__(self, field_name, offset, FieldTypeStruct(field_type), size, False)
        structure.AnonymousRecord.set_name(self, field_name)
        #structure.AnonymousRecord.add_fields(self, fields)
        _record_type = structure.RecordType(field_type, size,fields)
        self.set_record_type(_record_type)
        return

    def get_typename(self):
        return '%s' % self.field_type

    @property
    def address(self):
        raise NotImplementedError('You cannot call address on a subrecord')


#    def to_string(self, *args):
#        # print self.fields
#        fieldsString = '[ \n%s ]' % (''.join([field.to_string(self, '\t') for field in self.get_fields()]))
#        info = 'rlevel:%d SIG:%s size:%d' % (self.get_reverse_level(), self.get_signature(), len(self))
#        ctypes_def = '''
#class %s(ctypes.Structure):  # %s
#  _fields_ = %s
#
#''' % (self.name, info, fieldsString)
#        return ctypes_def
