#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import pickle
import numbers
import weakref
import ctypes
import sys

import os

import lrucache


#
# AnonymousRecord is an instance
# when we start reversing, we create a RecordType with fields.
#
#

log = logging.getLogger('structure')

DEBUG_ADDRS = []


def make_filename(_context, _record):
    sdir = _context.get_folder_cache_structures()
    if not os.path.isdir(sdir):
        os.mkdir(sdir)
    return os.path.sep.join([sdir, str(_record)])


def make_filename_from_addr(_context, address):
    return make_filename(_context, 'struct_%x' % address)


def cache_load(_context, address):
    # FIXME: unused
    dumpname = _context.dumpname
    if not os.access(dumpname, os.F_OK):
        return None
    fname = make_filename_from_addr(_context, address)
    p = pickle.load(file(fname, 'r'))
    if p is None:
        return None
    p.set_memory_handler(_context.memory_handler)
    return p


def remap_load(_context, address, newmappings):
    # FIXME: used by obsolete code
    dumpname = _context.dumpname
    if not os.access(dumpname, os.F_OK):
        return None
    fname = make_filename_from_addr(_context, address)
    p = pickle.load(file(fname, 'r'))
    if p is None:
        return None
    # YES we do want to over-write _memory_handler and bytes
    p.set_memory_handler(_context.memory_handler)
    return p


def cache_load_all_lazy(_context):
    """
    reload all allocated records with a CacheWrapper.
    :param _context:
    :return:
    """
    dumpname = _context.dumpname
    addresses = _context.list_allocations_addresses()
    for addr in addresses:
        try:
            yield addr, CacheWrapper(_context, addr)
        except ValueError as e:
            log.debug('Record 0x%x not found in cache', addr)
            ##raise e
            # we do not want to return in error.
            # try to load as many as possible.
    return


class CacheWrapper:
    """
    this is kind of a weakref proxy, but hashable
    """
    # TODO put that refs in the context
    refs = lrucache.LRUCache(5000)
    # duh, it works ! TODO: .saveme() on cache eviction
    # but there is no memory reduction as the GC does not collect that shit.
    # i would guess too many fields, map, context...

    def __init__(self, _context, address):
        self.address = address
        self._fname = make_filename_from_addr(_context, address)
        if not os.access(self._fname, os.F_OK):
            raise ValueError("%s does not exists" % self._fname)
        self._memory_handler = _context.memory_handler
        self.obj = None

    def __getattr__(self, *args):
        if self.obj is None or self.obj() is None:  #
            self._load()
        return getattr(self.obj(), *args)

    def unload(self):
        if self.address in CacheWrapper.refs:
            del CacheWrapper.refs[self.address]
        self.obj = None

    def _load(self):
        if self.obj is not None:  #
            if self.obj() is not None:  #
                return self.obj()
        try:
            p = pickle.load(file(self._fname, 'r'))
        except EOFError as e:
            log.error('Could not load %s - removing it %s', self._fname, e)
            os.remove(self._fname)
            raise e  # bad file removed
        if not isinstance(p, AnonymousRecord):
            raise EOFError("not a AnonymousRecord in cache. %s", p.__class__)
        if isinstance(p, CacheWrapper):
            raise TypeError("Why is a cache wrapper pickled?")
        p.set_memory_handler(self._memory_handler)
        p._dirty = False
        CacheWrapper.refs[self.address] = p
        self.obj = weakref.ref(p)
        return

    def save(self):
        if self.obj() is None:
            return
        self.obj().save()

    def __setstate__(self, d):
        log.error('setstate %s' % d)
        raise TypeError

    def __getstate__(self):
        log.error('getstate %s' % self.__dict__)
        raise TypeError

    def __hash__(self):
        return hash(self.address)

    def __cmp__(self, other):
        return cmp(self.address, other.address)

    def __str__(self):
        return 'struct_%x' % self.address


class StructureNotResolvedError(Exception):
    pass


# should not be a new style class
class AnonymousRecord(object):
    """
    AnonymousRecord in absolute address space.
    Comparison between struct is done is relative address space.
    """

    def __init__(self, memory_handler, _address, size, prefix=None):
        """
        Create a record instance representing an allocated chunk to reverse.
        :param memory_handler: the memory_handler of the allocated chunk
        :param _address: the address of the allocated chunk
        :param size: the size of the allocated chunk
        :param prefix: the name prefix to identify the allocated chunk
        :return:
        """
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()
        self.__address = _address
        if size <= 0:
            raise ValueError("a record should have a positive size")
        self._size = size
        self._reverse_level = 0
        self.__record_type = RecordType('struct_%x' % self.__address, self._size, [])
        self.reset()  # set fields
        self.set_name(prefix)
        return

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets a name for this record.
        :param name: name root for the record
        :return:
        """
        print "setter"
        if name is None:
            self._name = self.__record_type.name
        else:
            self._name = '%s_%x' % (name, self.__address)

    def set_name(self, name):
        # deprecated
        if name is None:
            self._name = self.__record_type.name
        else:
            self._name = '%s_%x' % (name, self.__address)

    def get_name(self):
        return self._name

    @property
    def address(self):
        return self.__address

    @property
    def record_type(self):
        return self.__record_type

    @property  # TODO add a cache property ?
    def bytes(self):
        if self._bytes is None:
            m = self._memory_handler.get_mapping_for_address(self.__address)
            self._bytes = m.read_bytes(self.__address, self._size)
            # TODO re_string.Nocopy
        return self._bytes

    def reset(self):
        self._resolved = False
        self._resolvedPointers = False
        self._reverse_level = 0
        self._dirty = True
        self._ctype = None
        self._bytes = None
        self.__final = False
        return

    def set_record_type(self, record_type, final_type=False):
        """
        Assign a reversed record type to this instance.
        That will change the fields types and render this record immutable.
        Any change will have to change the type of this record.
        :param t:
        :return:
        """
        self.__record_type = record_type
        self.__final = final_type

    def get_fields(self):
        """
        Return the reversed fields for this record

        :return: list(Field)
        """
        # we have to check for RecordField
        # return [f for f in self.__record_type.get_fields()]
        from haystack.reverse import fieldtypes
        _fields = []
        for f in self.__record_type.get_fields():
            if f.is_record():
                _fields.append(fieldtypes.RecordField(self, f.offset, f.name, f.field_type.name, f.get_fields()))
            else:
                _fields.append(f)
        return _fields

    def get_field(self, name):
        """
        Return the field named id
        :param name:
        :return:
        """
        for f in self.get_fields():
            if f.name == name:
                return f
        raise ValueError('No such field named %s', name)

    def saveme(self, _context):
        """
        Cache the structure to file if required.

        :return:
        """
        if not self._dirty:
            return
        # double check that the cache folder exists
        sdir = _context.get_folder_cache_structures()
        # create the cache filename for this structure
        fname = make_filename(_context, self)
        try:
            # FIXME : loops create pickle loops
            # print self.__dict__.keys()
            log.debug('saving to %s', fname)
            pickle.dump(self, file(fname, 'w'))
        except pickle.PickleError as e:
            # self.struct must be cleaned.
            log.error("Pickling error, file %s removed", fname)
            os.remove(fname)
            raise e
        except TypeError as e:
            log.error(e)
            # FIXME pickling a cachewrapper ????
            #import code
            #code.interact(local=locals())
        except RuntimeError as e:
            log.error(e)
            print self.to_string()
            # FIXME: why silent removal igore
        except KeyboardInterrupt as e:
            # clean it, its stale
            os.remove(fname)
            log.warning('removing %s' % fname)
            ex = sys.exc_info()
            raise ex[1], None, ex[2]
        return

    def get_field_at_offset(self, offset):
        """
        returns the field at a specific offset in this structure

        :param offset:
        :return:
        """
        if offset < 0 or offset > len(self):
            raise IndexError("Invalid offset")
        if self.get_reverse_level() < 10:
            raise StructureNotResolvedError("Reverse level %d is too low for record 0x%x", self.get_reverse_level(), self.address)
        # find the field
        ret = [f for f in self.get_fields() if f.offset == offset]
        if len(ret) == 0:
            # then check for closest match
            ret = sorted([f for f in self.get_fields() if f.offset < offset])
            if len(ret) == 0:
                raise ValueError("Offset 0x%x is not in structure?!" % offset)  # not possible
            # the last field standing is the one ( ordered fields)
            ret = ret[-1]
            if offset < ret.offset + len(ret):
                return ret
            # in between fields. Can happens on un-analyzed structure.
            # or byte field
            raise IndexError('Offset 0x%x is in middle of field at offset 0x%x' % offset, ret.offset)
        elif len(ret) != 1:
            raise RuntimeError("there shouldn't multiple fields at the same offset")
        #ret.sort()
        return ret[0]

    def set_memory_handler(self, memory_handler):
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()

    def get_reverse_level(self):
        return self._reverse_level

    def set_reverse_level(self, level):
        self._reverse_level = level

    def to_string(self):
        # print self.fields
        self.get_fields().sort()
        field_string_lines = []
        for field in self.get_fields():
            field_value = self.get_value_for_field(field)
            field_string_lines.append('\t'+field.to_string(field_value))
        fieldsString = '[ \n%s ]' % (''.join(field_string_lines))
        info = 'rlevel:%d SIG:%s size:%d' % (self.get_reverse_level(), self.get_signature_text(), len(self))
        final_ctypes = 'ctypes.Structure'
        # no renaming in instances..
        # if self.__final:
        #    final_ctypes = self.__record_type.name
        #    ctypes_def = '''
        #%s = %s  # %s
        #
        #''' % (self.get_name(), final_ctypes, info)
        # else:
        ctypes_def = '''
class %s(%s):  # %s
  _fields_ = %s

''' % (self.get_name(), final_ctypes, info, fieldsString)
        return ctypes_def

    def __contains__(self, other):
        """
        Returns true if other is an address included in the record's address space.

        :param other: a memory address
        :return:
        """
        if isinstance(other, numbers.Number):
            # test vaddr in struct instance len
            if self.__address <= other <= self.__address + len(self):
                return True
            return False
        else:
            raise NotImplementedError(type(other))

    def __getitem__(self, i):
        """
        Return the i-th fields of the structure.

        :param i:
        :return:
        """
        return self.get_fields()[i]

    def __len__(self):
        """
        Return the size of the record allocated space.
        :return:
        """
        return int(self._size)

    def __cmp__(self, other):
        if not isinstance(other, AnonymousRecord):
            return -1
        return cmp(self.__address, other.__address)

    def __getstate__(self):
        """ the important fields are
            _resolvedPointers
            _dirty
            _vaddr
            _name
            _resolved
            _ctype
            _size
            _fields
        """
        d = self.__dict__.copy()
        try:
            d['dumpname'] = os.path.normpath(self._memory_handler.get_name())
        except AttributeError as e:
            #log.error('no _memory_handler name in %s \n attribute error for %s %x \n %s'%(d, self.__class__, self.vaddr, e))
            d['dumpname'] = None
        d['_memory_handler'] = None
        d['_bytes'] = None
        d['_target'] = None
        return d

    def __setstate__(self, d):
        self.__dict__ = d
        if '_name' not in d:
            self.set_name(None)
        return

    def __str__(self):
        # FIXME, that should probably return self._name
        # BUT we need to ensure it does not impact the cache name
        return 'struct_%x' % self.__address

    ### pieces of codes that need review.

    def get_signature_text(self):
        return ''.join(['%s%d' % (f.get_signature()[0].signature, f.get_signature()[1]) for f in self.get_fields()])

    def get_signature(self):
        return [f.get_signature() for f in self.get_fields()]

    def get_type_signature_text(self):
        return ''.join([f.get_signature()[0].signature.upper() for f in self.get_fields()])

    def get_type_signature(self):
        return [f.get_signature()[0] for f in self.get_fields()]

    def get_value_for_field(self, _field, max_len=120):
        my_bytes = self._get_value_for_field(_field, max_len)
        if isinstance(my_bytes, str):
            bl = len(str(my_bytes))
            if bl >= max_len:
                my_bytes = my_bytes[:max_len / 2] + '...' + \
                    my_bytes[-(max_len / 2):]  # idlike to see the end
        return my_bytes

    def _get_value_for_field(self, _field, max_len=120):
        from haystack.reverse import fieldtypes
        word_size = self._target.get_word_size()
        if len(_field) == 0:
            return '<-haystack no pattern found->'
        if _field.is_string():
            if _field.field_type == fieldtypes.STRING16:
                try:
                    my_bytes = "%s" % (repr(self.bytes[_field.offset:_field.offset + _field.size].decode('utf-16')))
                except UnicodeDecodeError as e:
                    log.error('ERROR ON : %s', repr(self.bytes[_field.offset:_field.offset + _field.size]))
                    my_bytes = self.bytes[_field.offset:_field.offset + _field.size]
            else:
                my_bytes = "'%s'" % (self.bytes[_field.offset:_field.offset + _field.size])
        elif _field.is_integer():
            # what about endianness ?
            endianess = '<' # FIXME dsa self.endianess
            data = self.bytes[_field.offset:_field.offset + word_size]
            val = self._target.get_target_ctypes_utils().unpackWord(data, endianess)
            return val
        elif _field.is_zeroes():
            my_bytes = repr('\\x00'*len(_field))
        elif _field.is_array():
            my_bytes = self.bytes[_field.offset:_field.offset + len(_field)]
        elif _field.padding or _field.field_type == fieldtypes.UNKNOWN:
            my_bytes = self.bytes[_field.offset:_field.offset + len(_field)]
        elif _field.is_pointer():
            data = self.bytes[_field.offset:_field.offset + word_size]
            if len(data) != word_size:
                print repr(data), len(data)
                import pdb
                pdb.set_trace()
            val = self._target.get_target_ctypes_utils().unpackWord(data)
            return val
        else:  # bytearray, pointer...
            my_bytes = self.bytes[_field.offset:_field.offset + len(_field)]
        return my_bytes


class RecordType(object):
    """
    The type of a record.

    """
    def __init__(self, name, size, fields):
        self.name = name
        self.__size = int(size)
        self.__fields = fields
        self.__fields.sort()

    def get_fields(self):
        return [x for x in self.__fields]

    def __len__(self):
        return int(self.__size)

    def to_string(self):
        # print self.fields
        self.__fields.sort()
        field_string_lines = []
        for field in self.__fields:
            field_string_lines.append('\t'+field.to_string(None))
        fields_string = '[ \n%s ]' % (''.join(field_string_lines))
        info = 'size:%d' % len(self)
        ctypes_def = '''
class %s(ctypes.Structure):  # %s
  _fields_ = %s

''' % (self.name, info, fields_string)
        return ctypes_def


class ReversedType(ctypes.Structure):
    """
    A reversed record type.

    TODO: explain the usage.
    """

    @classmethod
    def create(cls, _context, name):
        ctypes_type = _context.get_reversed_type(name)
        if ctypes_type is None:  # make type an register it
            ctypes_type = type(name, (cls,), {'_instances': dict()})  # leave _fields_ out
            _context.add_reversed_type(name, ctypes_type)
        return ctypes_type

    @classmethod
    def addInstance(cls, anonymousStruct):
        """
        add the instance to be a instance of this type

        :param anonymousStruct:
        :return:
        """
        vaddr = anonymousStruct._vaddr
        cls._instances[vaddr] = anonymousStruct

    #@classmethod
    # def setFields(cls, fields):
    #  cls._fields_ = fields

    @classmethod
    def getInstances(cls):
        return cls._instances

    @classmethod
    def makeFields(cls, _context):
        # print '****************** makeFields(%s, context)'%(cls.__name__)
        root = cls.getInstances().values()[0]
        # try:
        for f in root.get_fields():
            print f, f.get_ctype()
        cls._fields_ = [(f.get_name(), f.get_ctype()) for f in root.get_fields()]
        # except AttributeError,e:
        #  for f in root.getFields():
        #    print 'error', f.get_name(), f.getCtype()

    #@classmethod
    def to_string(self):
        fieldsStrings = []
        for attrname, attrtyp in self.get_fields():  # model
            # FIXME need ctypesutils.
            if self.ctypes.is_pointer_type(attrtyp) and not self.ctypes.is_pointer_to_void_type(attrtyp):
                fieldsStrings.append('(%s, ctypes.POINTER(%s) ),\n' % (attrname, attrtyp._type_.__name__))
            else:  # pointers not in the heap.
                fieldsStrings.append('(%s, %s ),\n' % (attrname, attrtyp.__name__))
        fieldsString = '[ \n%s ]' % (''.join(fieldsStrings))

        info = 'size:%d' % (self.ctypes.sizeof(self))
        ctypes_def = '''
class %s(ctypes.Structure):  # %s
  _fields_ = %s

''' % (self.__name__, info, fieldsString)
        return ctypes_def

