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

from haystack.reverse import fieldtypes
# FieldType, makeArrayField
import pattern
import lrucache

log = logging.getLogger('structure')

DEBUG_ADDRS = []


def make_filename(context, st):
    sdir = context.get_folder_cache_structures()
    if not os.path.isdir(sdir):
        os.mkdir(sdir)
    return os.path.sep.join([sdir, str(st)])


def make_filename_from_addr(context, addr):
    return make_filename(context, 'struct_%x' % addr)


def makeStructure(context, start, size):
    return AnonymousRecord(context, start, size)


def cacheLoad(context, addr):
    dumpname = context.dumpname
    if not os.access(dumpname, os.F_OK):
        return None
    fname = make_filename_from_addr(context, addr)
    p = pickle.load(file(fname, 'r'))
    if p is None:
        return None
    p._set_context(context)
    return p


def cacheLoadAll(context):
    dumpname = context.dumpname
    addresses = context.listStructuresAddresses()
    for addr in addresses:
        fname = make_filename_from_addr(context, addr)
        if os.access(fname, os.F_OK):
            p = pickle.load(file(fname, 'r'))
            p._set_context(context)
            yield addr, p
    return


def remapLoad(context, addr, newmappings):
    dumpname = context.dumpname
    if not os.access(dumpname, os.F_OK):
        return None
    fname = make_filename_from_addr(context, addr)
    p = pickle.load(file(fname, 'r'))
    if p is None:
        return None
    # YES we do want to over-write _memory_handler and bytes
    p._set_context(context)
    return p


def cacheLoadAllLazy(ctx):
    dumpname = ctx.dumpname
    addresses = ctx.list_allocations_addresses()
    for addr in addresses:
        try:
            yield addr, CacheWrapper(ctx, addr)
        except ValueError as e:
            log.debug('Record 0x%x not found in cache', addr)
            ##raise e
            # we do not want to return in error.
            # try to load as many as possible.
    return


class CacheWrapper:  # this is kind of a weakref proxy, but hashable
    # TODO put that refs in the context
    refs = lrucache.LRUCache(5000)
    # duh, it works ! TODO: .saveme() on cache eviction
    # but there is no memory reduction as the GC does not collect that shit.
    # i would guess too many fields, map, context...

    def __init__(self, context, addr):
        self._addr = addr
        self._fname = make_filename_from_addr(context, addr)
        if not os.access(self._fname, os.F_OK):
            raise ValueError("%s does not exists" % self._fname)
        self._context = context
        self.obj = None

    def __getattr__(self, *args):
        if self.obj is None or self.obj() is None:  #
            self._load()
        return getattr(self.obj(), *args)

    def unload(self):
        if self._addr in CacheWrapper.refs:
            del CacheWrapper.refs[self._addr]
        self.obj = None

    def _load(self):
        if self.obj is not None:  #
            if self.obj() is not None:  #
                return self.obj()
        try:
            p = pickle.load(file(self._fname, 'r'))
        except EOFError as e:
            log.error('Could not load %s - removing it ' % (self._fname))
            os.remove(self._fname)
            raise e  # bad file removed
        if not isinstance(p, AnonymousRecord):
            raise EOFError("not a AnonymousRecord in cache. %s", p.__class__)
        p._set_context(self._context)
        p._dirty = False
        CacheWrapper.refs[self._addr] = p
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
        return hash(self._addr)

    def __cmp__(self, other):
        return cmp(self._addr, other._addr)

    def __str__(self):
        return 'struct_%x' % (self._vaddr)


class StructureNotResolvedError(Exception):
    pass


# should not be a new style class
class AnonymousRecord(object):
    """
    AnonymousRecord in absolute address space.
    Comparaison between struct is done is relative addresse space.
    """

    def __init__(self, context, vaddr, size, prefix=None):
        """
        Create a record instance representing an allocated chunk to reverse.
        :param context: the context of the allocated chunk
        :param vaddr: the address of the allocated chunk
        :param size: the size of the allocated chunk
        :param prefix: the name prefix to identify the allocated chunk
        :return:
        """
        self._context = context
        self._target = self._context.memory_handler.get_target_platform()
        self._vaddr = vaddr
        self._size = size
        self.reset()  # set fields
        self.set_name(prefix)
        return

    def set_name(self, name):
        """
        Sets a name for this record.
        :param name: name root for the record
        :return:
        """
        if name is None:
            self._name = 'struct_%x' % self._vaddr
        else:
            self._name = '%s_%x' % (name, self._vaddr)

    def get_name(self):
        return self._name

    def set_ctype(self, t):
        """
        Assign a known ctype record type to this instance
        :param t:
        :return:
        """
        self._ctype = t

    def get_ctype(self):
        if self._ctype is None:
            raise TypeError('Structure has no type')
        return self._ctype

    def reset(self):
        self._fields = []
        self._resolved = False
        self._resolvedPointers = False
        self._dirty = True
        self._ctype = None
        self._bytes = None
        return

    def add_fields(self, fields):
        """
        Assign fields to this structure.

        :param fields: list of fieldtypes.Field
        :return:
        """
        self._fields.extend(fields)

    def saveme(self):
        """
        Cache the structure to file if required.

        :return:
        """
        if not self._dirty:
            return
        # double check that the cache folder exists
        sdir = self._context.get_folder_cache_structures()
        if not os.path.isdir(sdir):
            os.mkdir(sdir)
        # create the cache filename for this structure
        fname = make_filename(self._context, self)
        try:
            # FIXME : loops create pickle loops
            # print self.__dict__.keys()
            log.debug('saving to %s', fname)
            pickle.dump(self, file(fname, 'w'))
        except pickle.PickleError as e:
            # self.struct must be cleaned.
            log.error("Pickling error, file %s removed",fname)
            os.remove(fname)
            raise e
        except RuntimeError as e:
            log.error(e)
            print self.to_string()
        except KeyboardInterrupt as e:
            # clean it, its stale
            os.remove(fname)
            log.warning('removing %s' % (fname))
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
        log.debug('Looking at child %s %s', self.to_string(), self.is_resolved())
        log.debug('Looking at child structure ID %d' % id(self))
        if not self.is_resolved():
            raise StructureNotResolvedError("Please run BasicCachingReverser at least once on this record")
        # find the field
        ret = [f for f in self._fields if f.offset == offset]
        if len(ret) == 0:
            # then check for closest match
            ret = sorted([f for f in self._fields if f.offset < offset])
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

    def get_fields(self):
        """
        Return the reversed fields for this record

        :return: list(Field)
        """
        return [f for f in self._fields]

    def get_pointer_fields(self):
        """
        Return the list of fields that are pointer type fields

        :return: list(Field)
        """
        return [f for f in self._fields if f.is_pointer()]

    def _set_context(self, context):
        self._context = context

    @property
    def _memory_handler(self):
        return self._context.memory_handler

    @property  # TODO add a cache property ?
    def bytes(self):
        if self._bytes is None:
            m = self._memory_handler.get_mapping_for_address(self._vaddr)
            self._bytes = m.read_bytes(
                self._vaddr,
                self._size)  # TODO re_string.Nocopy
        return self._bytes

    # TODO replace by a numerical "reverse progression" index.
    def is_resolved(self):
        return self._resolved

    def set_resolved(self):
        self._resolved = True

    def is_resolvedPointers(self):
        return self._resolvedPointers

    def to_string(self):
        # print self.fields
        self._fields.sort()
        fieldsString = '[ \n%s ]' % (
            ''.join([field.to_string('\t') for field in self._fields]))
        info = 'resolved:%s SIG:%s size:%d' % (
            self.is_resolved(), self.getSignature(text=True), len(self))
        if len(self.get_pointer_fields()) != 0:
            info += ' resolvedPointers:%s' % (self.is_resolvedPointers())
        ctypes_def = '''
class %s(ctypes.Structure):  # %s
  _fields_ = %s

''' % (self.get_name(), info, fieldsString)
        return ctypes_def

    def __contains__(self, other):
        """
        Returns true if other is an address included in the record's address space.

        :param other: a memory address
        :return:
        """
        if isinstance(other, numbers.Number):
            # test vaddr in struct instance len
            if self._vaddr <= other <= self._vaddr + len(self):
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
        return self._fields[i]

    def __len__(self):
        """
        Return the size of the record allocated space.
        :return:
        """
        return int(self._size)

    def __cmp__(self, other):
        if not isinstance(other, AnonymousRecord):
            return -1
        return cmp(self._vaddr, other._vaddr)

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
            d['dumpname'] = os.path.normpath(self._memory_handler.name)
        except AttributeError as e:
            #log.error('no _memory_handler name in %s \n attribute error for %s %x \n %s'%(d, self.__class__, self.vaddr, e))
            d['dumpname'] = None
        d['_context'] = None
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
        return 'struct_%x' % self._vaddr

    ### pieces of codes that need review.
    def _aggregateFields(self):
        # if not self.resolvedPointers:
        #  raise ValueError('I should be resolved')
        self._dirty = True

        self._fields.sort()
        myfields = []

        signature = self.getSignature()
        pencoder = pattern.PatternEncoder(signature, minGroupSize=3)
        patterns = pencoder.makePattern()

        #txt = self.getSignature(text=True)
        #log.warning('signature of len():%d, %s'%(len(txt),txt))
        #p = pattern.findPatternText(txt, 2, 3)
        # log.debug(p)

        #log.debug('aggregateFields came up with pattern %s'%(patterns))

        # pattern is made on FieldType,
        # so we need to dequeue self.fields at the same time to enqueue in
        # myfields
        for nb, fieldTypesAndSizes in patterns:
            # print 'fieldTypesAndSizes:',fieldTypesAndSizes
            if nb == 1:
                fieldType = fieldTypesAndSizes[0]  # its a tuple
                field = self._fields.pop(0)
                myfields.append(field)  # single el
                #log.debug('simple field:%s '%(field) )
            # array of subtructure DEBUG XXX TODO
            elif len(fieldTypesAndSizes) > 1:
                log.debug('substructure with sig %s' % (fieldTypesAndSizes))
                myelements = []
                for i in range(nb):
                    fields = [ self._fields.pop(0) for i in range(len(fieldTypesAndSizes))]  # nb-1 left
                    #otherFields = [ self.fields.pop(0) for i in range((nb-1)*len(fieldTypesAndSizes)) ]
                    # need global ref to compare substructure signature to
                    # other anonstructure
                    firstField = fieldtypes.FieldType.makeStructField(
                        self,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = fieldtypes.makeArrayField(self, myelements)
                myfields.append(array)
                #log.debug('array of structure %s'%(array))
            elif len(fieldTypesAndSizes) == 1:  # make array of elements or
                log.debug("found array of %s",  self._fields[0].typename.basename)
                fields = [self._fields.pop(0) for i in range(nb)]
                array = fieldtypes.makeArrayField(self, fields)
                myfields.append(array)
                #log.debug('array of elements %s'%(array))
            else:  # TODO DEBUG internal struct
                raise ValueError("fields patterns len is incorrect %d" % len(fieldTypesAndSizes))

        log.debug('done with aggregateFields')
        self._fields = myfields
        # print 'final', self.fields
        return


    def _findSubStructures(self):
        if not self.resolvedPointers:
            raise ValueError('I should be resolved')
        self._dirty = True

        self._fields.sort()
        myfields = []

        signature = self.getTypeSignature()
        pencoder = pattern.PatternEncoder(signature, minGroupSize=2)
        patterns = pencoder.makePattern()

        txt = self.getTypeSignature(text=True)
        p = pattern.findPatternText(txt, 1, 2)

        log.debug('substruct typeSig: %s' % txt)
        log.debug('substruct findPatterntext: %s' % p)
        log.debug('substruct came up with pattern %s' % (patterns))

        # pattern is made on FieldType,
        # so we need to dequeue self.fields at the same time to enqueue in
        # myfields
        for nb, fieldTypes in patterns:
            if nb == 1:
                field = self._fields.pop(0)
                myfields.append(field)  # single el
                #log.debug('simple field:%s '%(field) )
            elif len(fieldTypes) > 1:  # array of subtructure DEBUG XXX TODO
                log.debug('fieldTypes:%s' % fieldTypes)
                log.debug('substructure with sig %s' %
                          (''.join([ft.sig[0] for ft in fieldTypes])))
                myelements = []
                for i in range(nb):
                    fields = [
                        self._fields.pop(0) for i in range(
                            len(fieldTypes))]  # nb-1 left
                    #otherFields = [ self.fields.pop(0) for i in range((nb-1)*len(fieldTypesAndSizes)) ]
                    # need global ref to compare substructure signature to
                    # other anonstructure
                    firstField = fieldtypes.FieldType.makeStructField(
                        self,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = fieldtypes.makeArrayField(self, myelements)
                myfields.append(array)
                #log.debug('array of structure %s'%(array))
            # make array of elements obase on same base type
            elif len(fieldTypes) == 1:
                log.debug(
                    'found array of %s' %
                    (self._fields[0].typename.basename))
                fields = [self._fields.pop(0) for i in range(nb)]
                array = fieldtypes.makeArrayField(self, fields)
                myfields.append(array)
                #log.debug('array of elements %s'%(array))
            else:  # TODO DEBUG internal struct
                raise ValueError(
                    'fields patterns len is incorrect %d' %
                    (len(fieldTypes)))

        log.debug('done with findSubstructure')
        self._fields = myfields
        # print 'final', self.fields
        return

    def getSignature(self, text=False):
        if text:
            return ''.join(
                ['%s%d' % (f.getSignature()[0].sig, f.getSignature()[1]) for f in self._fields])
        return [f.getSignature() for f in self._fields]

    def getTypeSignature(self, text=False):
        if text:
            return ''.join([f.getSignature()[0].sig.upper()
                            for f in self._fields])
        return [f.getSignature()[0] for f in self._fields]


class ReversedType(ctypes.Structure):
    """
    A reversed record type.

    TODO: explain the usage.
    """

    @classmethod
    def create(cls, context, name):
        ctypes_type = context.getReversedType(name)
        if ctypes_type is None:  # make type an register it
            ctypes_type = type(
                name, (cls,), {
                    '_instances': dict()})  # leave _fields_ out
            context.addReversedType(name, ctypes_type)
        return ctypes_type

    ''' add the instance to be a instance of this type '''
    @classmethod
    def addInstance(cls, anonymousStruct):
        vaddr = anonymousStruct._vaddr
        cls._instances[vaddr] = anonymousStruct

    #@classmethod
    # def setFields(cls, fields):
    #  cls._fields_ = fields

    @classmethod
    def getInstances(cls):
        return cls._instances

    @classmethod
    def makeFields(cls, context):
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

