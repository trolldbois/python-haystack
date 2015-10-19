#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import ctypes

from haystack.reverse import config

"""
the Python classes to represent the guesswork record and field typing of
allocations.
"""


log = logging.getLogger('field')

# Field related functions and classes


def findFirstNot(s, c):
    for i in xrange(len(s)):
        if s[i] != c:
            return i
    return -1


def makeArrayField(parent, fields):
    #vaddr = parent.vaddr+firstField.offset
    newField = ArrayField(parent, fields)
    return newField


class FieldType(object):
    """
    Represents the type of a field.
    """
    types = set()

    def __init__(self, _id, basename, typename, ctype, sig, isPtr=False):
        self._id = _id
        self.basename = basename
        self.ctypes = typename
        self._ctype = ctype
        self.sig = sig
        self.isPtr = isPtr

    @classmethod
    def makePOINTER(cls, typ):
        if typ == FieldType.STRING:
            return FieldType.STRING_POINTER
        return cls(typ._id + 0xa, typ.basename + '_ptr',
                   'ctypes.POINTER(%s)' % (typ.ctypes), 'P', True)

    @classmethod
    # struct name should be the vaddr... otherwise it gonna be confusing
    def makeStructField(cls, parent, offset, typename, fields, field_name=None):
        """
        make a structure type
        """
        import structure
        _address = parent.address + offset
        if field_name is None:
            field_name = '%lx' % _address
        newfieldType = FieldTypeStruct(typename, field_name, fields)
        newfieldType.setStruct(structure.AnonymousRecord(parent._memory_handler, _address, len(newfieldType)))
        newField = Field(parent, offset, newfieldType, len(newfieldType), False)
        # FIXME should parent be changed on substructure ?
        # should the offset be changed here too ?
        # should newfieldType.set_parent() be called too ?
        return newField

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

    def __init__(self, typename, name, fields):
        super(FieldTypeStruct, self).__init__(0x1, name, typename, 'K', 'K', isPtr=False)
        self.size = sum([len(f) for f in fields])
        self.elements = fields
        # TODO s2[0].elements[0].typename.elements[0] is no good

    def setStruct(self, struct):
        self._struct = struct

    def getStruct(self):
        return self._struct

    def __len__(self):
        return self.size


class FieldTypeArray(FieldType):
    """
    An array type
    """
    def __init__(self, basicTypeName):
        super(FieldTypeArray, self).__init__(self, 0x60, 'array_%s' % basicTypeName, None, 'a', isPtr=False)


# setup all the know types that are interesting to us
FieldType.UNKNOWN = FieldType(0x0, 'untyped', 'ctypes.c_ubyte', ctypes.c_ubyte, 'u')
FieldType.STRUCT = FieldType(0x1, 'struct', 'Structure', None, 'K')
FieldType.ZEROES = FieldType(0x2, 'zerroes', 'ctypes.c_ubyte', ctypes.c_ubyte, 'z')
FieldType.STRING = FieldType(0x4, 'text', 'ctypes.c_char', ctypes.c_char, 'T')
FieldType.STRING16 = FieldType(0x14, 'utf16', 'ctypes.c_char', ctypes.c_char, 'T')
FieldType.STRINGNULL = FieldType(0x6, 'text0', 'ctypes.c_char', ctypes.c_char, 'T')
FieldType.STRING_POINTER = FieldType(0x4 + 0xa, 'text_ptr', 'ctypes.c_char_p', ctypes.c_char_p, 's', True)
FieldType.INTEGER = FieldType(0x18, 'int', 'ctypes.c_uint', ctypes.c_uint, 'I')
FieldType.SMALLINT = FieldType(0x8, 'small_int', 'ctypes.c_uint', ctypes.c_uint, 'i')
FieldType.SIGNED_SMALLINT = FieldType(0x28, 'signed_small_int', 'ctypes.c_int', ctypes.c_uint, 'i')
FieldType.ARRAY = FieldType(0x40, 'array', 'Array', None, 'a')
FieldType.BYTEARRAY = FieldType(0x50, 'array', 'ctypes.c_ubyte', ctypes.c_ubyte, 'a')
#FieldType.ARRAY_CHAR_P = FieldType(0x9, 'array_char_p',     'ctypes.c_char_p',   'Sp')
FieldType.POINTER = FieldType(0xa, 'ptr', 'ctypes.c_void_p', ctypes.c_void_p, 'P', True)
FieldType.PADDING = FieldType(0xff, 'pad', 'ctypes.c_ubyte', ctypes.c_ubyte, 'X')


class Field(object):
    """
    Class that represent a Field instance, a FieldType instance.
    """
    def __init__(self, astruct, offset, typename, size, isPadding):
        self.struct = astruct
        self.offset = offset
        self.size = size
        # mhh not sure. what about array ?
        assert isinstance(typename, FieldType)
        self.typename = typename
        self._ctype = None
        self.padding = isPadding
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
        return self.typename in [
            FieldType.STRING, FieldType.STRING16, FieldType.STRINGNULL, FieldType.STRING_POINTER]

    def is_pointer(self):
        return issubclass(self.__class__, PointerField)

    def is_zeroes(self):
        return self.typename == FieldType.ZEROES

    def is_array(self):  # will be overloaded
        return self.typename == FieldType.ARRAY or self.typename == FieldType.BYTEARRAY

    def is_integer(self):
        return self.typename == FieldType.INTEGER or self.typename == FieldType.SMALLINT or self.typename == FieldType.SIGNED_SMALLINT

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
        elif self.typename == FieldType.UNKNOWN:
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
        i = 'new'
        try:
            if self in self.struct._fields:
                i = self.struct._fields.index(self)
        except ValueError as e:
            log.warning('self in struct.fields but not found by index()')
        except AttributeError as e:
            pass
        return '<Field %s offset:%d size:%s t:%s' % (
            i, self.offset, self.size, self.typename)

    def getValue(self, maxLen):
        bytes = self._getValue(maxLen)
        bl = len(str(bytes))
        if bl >= maxLen:
            bytes = bytes[:maxLen / 2] + '...' + \
                bytes[-(maxLen / 2):]  # idlike to see the end
        return bytes

    def _getValue(self, maxLen):
        if len(self) == 0:
            return '<-haystack no pattern found->'
        if self.is_string():
            if self.typename == FieldType.STRING16:
                try:
                    bytes = "%s" % (repr(
                        self.struct.bytes[
                            self.offset:self.offset + self.size].decode('utf-16')))
                except UnicodeDecodeError as e:
                    log.error(
                        'ERROR ON : %s' %
                        (repr(
                            self.struct.bytes[
                                self.offset:self.offset +
                                self.size])))
                    bytes = self.struct.bytes[
                        self.offset:self.offset +
                        self.size]
            else:
                bytes = "'%s'" % (
                    self.struct.bytes[self.offset:self.offset + self.size])
        elif self.is_integer():
            return self.value
        elif self.is_zeroes():
            bytes = repr(self.value)  # '\\x00'*len(self)
        elif self.is_array():
            log.warning('ARRAY in Field type, %s', self.typename)
            log.error('error in 0x%x offset 0x%x', self.struct.address, self.offset)
            bytes = ''.join(['[', ','.join([el.to_string() for el in self.elements]), ']'])
        elif self.padding or self.typename == FieldType.UNKNOWN:
            bytes = self.struct.bytes[self.offset:self.offset + len(self)]
        else:  # bytearray, pointer...
            return self.value
        return bytes

    def get_signature(self):
        return (self.typename, self.size)

    def to_string(self, prefix=''):
        # log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
        #    %(self.isPointer(), self.isInteger(), self.isZeroes(), self.padding, self.typename.basename) )

        if self.is_pointer():
            comment = '# @ 0x%0.8x %s %s' % (
                self.value, self.comment, self.usercomment)
        elif self.is_integer():
            comment = '#  0x%x %s %s' % (self.getValue(
                config.commentMaxSize),
                self.comment,
                self.usercomment)
        elif self.is_zeroes():
            comment = '''# %s %s zeroes: '\\x00'*%d''' % (
                self.comment, self.usercomment, len(self))
        elif self.is_string():
            comment = '#  %s %s %s: %s' % (self.comment,
                                           self.usercomment,
                                           self.typename.basename,
                                           self.getValue(
                                               config.commentMaxSize))
        else:
            # unknown
            comment = '# %s %s else bytes:%s' % (
                self.comment, self.usercomment, repr(self.getValue(config.commentMaxSize)))

        fstr = "%s( '%s' , %s ), %s\n" % (
            prefix, self.get_name(), self.get_typename(), comment)
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

    def __init__(self, *arg, **kwargs):
        super(PointerField, self).__init__(*arg, **kwargs)
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
    def __init__(self, astruct, elements):
        self.struct = astruct
        self.offset = elements[0].offset
        self.typename = FieldTypeArray(elements[0].typename.basename)

        self.elements = elements
        self.nbElements = len(elements)
        self.basicTypeSize = len(elements[0])
        self.basicTypename = elements[0].typename

        self.size = self.basicTypeSize * len(self.elements)

        super(ArrayField, self).__init__(astruct, self.offset, self.typename, self.size, False)

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

    def _getValue(self, maxLen):
        # show number of elements and elements types
        #bytes= ''.join(['[',','.join([str(el._getValue(10)) for el in self.elements]),']'])
        bytes = '%d x ' % (len(
            self.elements)) + ''.join(['[', ','.join([el.to_string('') for el in self.elements]), ']'])
        # thats for structFields
        #bytes= '%d x '%(len(self.elements)) + ''.join(['[',','.join([el.typename for el in el0.typename.elements]),']'])
        return bytes

    def to_string(self, prefix):
        log.debug('isPointer:%s isInteger:%s isZeroes:%s padding:%s typ:%s'
                  % (self.is_pointer(), self.is_integer(), self.is_zeroes(), self.padding, self.typename.basename))
        #
        comment = '# %s %s array:%s' % (
            self.comment, self.usercomment, self.getValue(config.commentMaxSize))
        fstr = "%s( '%s' , %s ), %s\n" % (
            prefix, self.get_name(), self.get_typename(), comment)
        return fstr


def isIntegerType(typ):
    return typ == FieldType.INTEGER or typ == FieldType.SMALLINT or typ == FieldType.SIGNED_SMALLINT

#def resize(field, new_offset, new_size):
#    if field.is_pointer():
#        raise TypeError("Cannot resize a pointer field")

