#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import pickle
import itertools
import numbers
import weakref
import ctypes
import sys

import os

from haystack.reverse import config
from fieldtypes import Field, FieldType, makeArrayField
import pattern
import utils
import lrucache

log = logging.getLogger('structure')

DEBUG_ADDRS = []


# a 12 Mo heap takes 30 minutes on my slow notebook
# what is \xb2 padding for ?
# huge bug with zerroes fields aggregation
# the empty space at the end of the heap is making the reverse quite
# slow.... logs outputs line rate 10/sec againt 2k/sec

# TODO look for VFT and malloc metadata ?
# se stdc++ to unmangle c++
# vivisect ?
# TODO 1: make an interactive thread on that anon_struct and a struct Comparator to find similar struct.
#         that is a first step towards structure identification && naming. + caching of info
#      2: dump ctypes structure into python file + cache (vaddr, Structurectypes ) to pickle file ( reloading/continue possible with less recalculation )
# create a typename for \xff * 8/16. buffer color ? array of char?

# Compare sruct type from parent with multiple pointer (

def make_filename(context, st):
    sdir = config.get_record_cache_folder_name(context.dumpname)
    if not os.path.isdir(sdir):
        os.mkdir(sdir)
    return os.path.sep.join([sdir, str(st)])


def make_filename_from_addr(context, addr):
    return make_filename(context, 'struct_%x' % (addr))


def makeStructure(context, start, size):
    return AnonymousStructInstance(context, start, size)


def cacheLoad(context, addr):
    dumpname = context.dumpname
    if not os.access(dumpname, os.F_OK):
        return None
    fname = make_filename_from_addr(context, addr)
    p = pickle.load(file(fname, 'r'))
    if p is None:
        return None
    p.setContext(context)
    return p


def cacheLoadAll(context):
    dumpname = context.dumpname
    addresses = context.listStructuresAddresses()
    for addr in addresses:
        fname = make_filename_from_addr(context, addr)
        if os.access(fname, os.F_OK):
            p = pickle.load(file(fname, 'r'))
            p.setContext(context)
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
    p.setContext(context)
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
        if not isinstance(p, AnonymousStructInstance):
            raise EOFError(
                'not a AnonymousStructInstance in cache. %s' %
                (p.__class__))
        p.setContext(self._context)
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
class AnonymousStructInstance(object):

    '''
    AnonymousStruct in absolute address space.
    Comparaison between struct is done is relative addresse space.
    '''

    def __init__(self, context, vaddr, size, prefix=None):
        self._context = context
        self._target = self._context.memory_handler.get_target_platform()
        self._vaddr = vaddr
        self._size = size
        self.reset()  # set fields
        self.setName(prefix)
        return

    def setName(self, name):
        if name is None:
            self._name = 'struct_%x' % (self._vaddr)
        else:
            self._name = '%s_%x' % (name, self._vaddr)

    def get_name(self):
        return self._name

    def set_ctype(self, t):
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

    def guessField(self, vaddr, typename=None, size=-1, padding=False):
        self._dirty = True
        offset = vaddr - self._vaddr
        if offset < 0 or offset > len(self):
            raise IndexError()
        if typename is None:
            typename = FieldType.UNKNOWN
        # find the maximum size
        if size == -1:
            try:
                nextStruct = itertools.dropwhile(
                    lambda x: (
                        x.offset < offset), sorted(
                        self._fields)).next()
                nextStructOffset = nextStruct.offset
            except StopIteration as e:
                nextStructOffset = len(self)
            maxFieldSize = nextStructOffset - offset
            size = maxFieldSize
        ##
        field = Field(self, offset, typename, size, padding)
        if typename == FieldType.UNKNOWN:
            if not field.decodeType():
                return None
        elif not field.check():
            return None
        if field.size < 0:
            raise ValueError('error here %s %s' % (field, field.typename))
        # field has been typed
        self._fields.append(field)
        self._fields.sort()
        return field

    def add_fields(self, fields):
        self._fields.extend(fields)

    def addFields(self, vaddrList, typename, size, padding):
        vaddrList.sort()
        if min(vaddrList) < self._vaddr or max(
                vaddrList) > self._vaddr + len(self):
            raise IndexError()
        if typename is None:
            raise ValueError()
        self._dirty = True
        fields = [
            Field(
                self,
                vaddr -
                self._vaddr,
                typename,
                size,
                padding) for vaddr in vaddrList]
        self._fields.extend(fields)
        self._fields.sort()
        return

    def addField(self, vaddr, typename, size, padding):
        self._dirty = True
        offset = vaddr - self._vaddr
        return self._addField(offset, typename, size, padding)

    def _addField(self, offset, typename, size, padding):
        if offset < 0 or offset > len(self):
            raise IndexError()
        if typename is None:
            raise ValueError()
        self._dirty = True
        # make a field with no autodecode
        field = Field(self, offset, typename, size, padding)
        # field has been typed
        self._fields.append(field)
        self._fields.sort()
        return field

    def saveme(self):
        if not self._dirty:
            return
        sdir = config.get_record_cache_folder_name(self._context.dumpname)
        if not os.path.isdir(sdir):
            os.mkdir(sdir)
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
            print self.toString()
        except KeyboardInterrupt as e:
            # clean it, its stale
            os.remove(fname)
            log.warning('removing %s' % (fname))
            ex = sys.exc_info()
            raise ex[1], None, ex[2]
        return

    def _check(self, field):
        # TODO check against other fields
        return field.check()

    def get_field_at_offset(self, offset):
        '''@ returns the field at a specific offset.'''
        log.debug('Looking at child %s %s', self.toString(), self.is_resolved())
        log.debug('Looking at child structure ID %d' % id(self))
        if not self.is_resolved():
            import pdb
            pdb.set_trace()
            raise StructureNotResolvedError()
        ret = [f for f in self._fields if f.offset == offset]
        if len(ret) == 0:  # then check for closest match
            ret = sorted([f for f in self._fields if f.offset < offset])
            if len(ret) == 0:
                raise ValueError(
                    'Offset 0x%x is not in structure?!' %
                    (offset))  # not possible
            ret = ret[-1]  # last field standing is the one ( ordered fields)
            if offset < ret.offset + len(ret):
                return ret
            # in between fields. Can happens on un-analyzed structure.
            # or byte field
            raise IndexError(
                'Offset 0x%x is in middle of field at offset 0x%x' %
                (offset, ret.offset))
        ret.sort()
        return ret[0]

    #@deprecated
    def decodeFields(self):
        ''' call analyser    '''
        raise NotImplementedError(
            'Please use haystack.reverse.heuristics.dsa.DSASimple')

    def resolvePointers(self):

        raise NotImplementedError(
            'Please use haystack.reverse.heuristics.dsa.EnrichedPointerFields')

        if self.resolvedPointers:
            return
        structs_addrs, structCache = None, None
        self._dirty = True
        resolved = 0
        pointerFields = self.getPointerFields()
        log.debug('got %d pointerfields' % (len(pointerFields)))
        known = 0
        inHeap = 0
        inMappings = 0
        undecoded = 0
        fromcache = 0
        for field in pointerFields:
            # shorcut
            if hasattr(field, '_ptr_resolved'):
                if field._ptr_resolved:
                    fromcache += 1
                    continue
            # if pointed is not None:  # erase previous info
            tgt = None
            try:
                tgt = self._context.get_structure_for_address(field.value)
                known += 1
                field.target_struct_addr = field.value
                # change the basic ctypes
                field.ctypes = 'ctypes.POINTER(%s)' % (tgt)
                if not tgt._resolved:  # fields have not been decoded yet
                    undecoded += 1
                    log.debug('target %s is undecoded' % (tgt))
                    continue
                field._target_field = tgt[0]  # first field of struct
            except KeyError as e:
                if field.value in self._heap:
                    # elif target is a STRING in the HEAP
                    # set pointer type to char_p
                    inHeap += 1
                    # TODO use context's helpers
                    tgt_struct, tgt_field = self._resolvePointerToStructField(
                        field)
                    field.target_struct_addr = tgt_struct._vaddr
                    if tgt_field is not None:
                        # field.ctypes = str(tgt_struct) # no
                        field.typename = FieldType.makePOINTER(
                            tgt_field.typename)
                        field._target_field = tgt_field
                        tgt = '%s_field_%s' % (
                            tgt_field.struct, tgt_field.getName())
                    else:
                        undecoded += 1
                        #log.debug('target %x is unresolvable in a field'%(field.value))
                    pass
                elif field.value in self._memory_handler:  # other _memory_handler
                    inMappings += 1
                    tgt = 'ext_lib_%d' % (field.offset)
                    field._ptr_to_ext_lib = True
                    field.target_struct_addr = self._memory_handler.get_mapping_for_address(
                        field.value).start
                    pass
            #
            if tgt is not None:
                resolved += 1
                field.setName('%s_%s' % (field.typename.basename, tgt))
                field._ptr_resolved = True
                #log.debug('resolved %s %s (%d)'%(field.getName(), field, resolved))
        log.debug('resolvePointers on t:%d,c:%d,r:%d, k:%d,h:%d,m:%d,u:%d' % (len(pointerFields),
                                                                              fromcache, resolved, known, inHeap, inMappings, undecoded))
        #
        if len(pointerFields) == (resolved + fromcache):
            if resolved != 0:
                log.debug('%s pointers are fully resolved' % (self))
            self._resolvedPointers = True
        else:
            self._resolvedPointers = False
        return

    # , structs_addrs, structCache):
    def _resolvePointerToStructField(self, field):
        raise NotImplementedError('Obselete')
        # TODO DEBUG, i got gaps in my memory _memory_handler structures
        #  struct_add16e8 -> struct_add173c
        # if len(structs_addrs) == 0:
        if len(self._context._malloc_addresses) == 0:
            raise TypeError
            # return None
        # TODO use context's helpers
        nearest_addr, ind = utils.closestFloorValue(
            field.value, self._context._malloc_addresses)
        log.debug('nearest_addr:%x ind:%d' % (nearest_addr, ind))
        tgt_st = self._context.get_structure_for_address(nearest_addr)
        if field.value % self.target.get_word_size() != 0:
            # non aligned, nothing could match
            return tgt_st, None
        log.debug('tgt_st %s' % tgt_st)
        if field.value in tgt_st:
            offset = field.value - nearest_addr
            for f in tgt_st._fields:
                if f.offset == offset:
                    tgt_field = f
                    log.debug('Found %s' % f)
                    return tgt_st, tgt_field
        log.debug('no field found')
        return tgt_st, None

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
                    fields = [
                        self._fields.pop(0) for i in range(
                            len(fieldTypesAndSizes))]  # nb-1 left
                    #otherFields = [ self.fields.pop(0) for i in range((nb-1)*len(fieldTypesAndSizes)) ]
                    # need global ref to compare substructure signature to
                    # other anonstructure
                    firstField = FieldType.makeStructField(
                        self,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = makeArrayField(self, myelements)
                myfields.append(array)
                #log.debug('array of structure %s'%(array))
            elif len(fieldTypesAndSizes) == 1:  # make array of elements or
                log.debug(
                    'found array of %s' %
                    (self._fields[0].typename.basename))
                fields = [self.fields.pop(0) for i in range(nb)]
                array = makeArrayField(self, fields)
                myfields.append(array)
                #log.debug('array of elements %s'%(array))
            else:  # TODO DEBUG internal struct
                raise ValueError(
                    'fields patterns len is incorrect %d' %
                    (len(fieldTypesAndSizes)))

        log.debug('done with aggregateFields')
        self._fields = myfields
        # print 'final', self.fields
        return

    '''
  # XX TODO DEBUG, this is not a substructure.
  '''

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
                    firstField = FieldType.makeStructField(
                        self,
                        fields[0].offset,
                        fields)
                    myelements.append(firstField)
                array = makeArrayField(self, myelements)
                myfields.append(array)
                #log.debug('array of structure %s'%(array))
            # make array of elements obase on same base type
            elif len(fieldTypes) == 1:
                log.debug(
                    'found array of %s' %
                    (self._fields[0].typename.basename))
                fields = [self._fields.pop(0) for i in range(nb)]
                array = makeArrayField(self, fields)
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

    def todo(self):
        # apply librairies structures search against heap before running anything else.
        # that should cut our reverse time way down
        # prioritize search per reverse struct size. limit to big struct and their graph.
        # then make a Named/Anonymous Struct out of them

        # Anonymous Struct should be a model.Structure.
        # it has to be dynamic generated, but that should be ok. we need a AnonymouStructMaker
        # in:anonymousStruct1
        # out:anonymousStruct2 # with new fields types and so on...
        # each algo has to be an ASMaker, so we can chain them.
        #
        # The controller/Reverser should keep structs coherency. and appli maker to each of them
        # the controller can have different heuristics to apply to struct :
        # * aggregates: char[][], buffers
        # * type definition: substructs, final reverse type step, c++ objects,

        # on each integer array, look indices for \x00
        # if there is a regular interval between \x00 in the sequence ( 5 char
        # then 0 ) then make some sub arrays, nul terminated

        # magic len approach on untyped bytearrays or array of int. - TRY TO ALIGN ON 2**x
        # if len(fields[i:i+n]) == 4096 // ou un exposant de 2 > 63 # m = math.modf(math.log( l, 2)) %% m[0] == 0.0 && m[1]>5.0
        # alors on a un buffer de taille l
        # fields[i:i+n] ne devrait contenir que du zeroes, untyped et int

        return

    def _isPointerToString(self, field):
        # pointer is Resolved
        if not field.isPointer():
            return False
        if hasattr(field, '_ptr_to_ext_lib'):
            return False
        # if not hasattr(field,'_target_field'):
        #  return False
        return field._target_field.isString()

    def get_fields(self):
        return [f for f in self._fields]

    def getPointerFields(self):
        return [f for f in self._fields if f.isPointer()]

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

    def setContext(self, context):
        self._context = context

    @property
    def _memory_handler(self):
        return self._context.memory_handler

    @property
    def _heap(self):
        return self._context.memory_handler.get_heap_mappings()

    @property  # TODO add a cache property ?
    def bytes(self):
        if self._bytes is None:
            m = self._memory_handler.get_mapping_for_address(self._vaddr)
            self._bytes = m.read_bytes(
                self._vaddr,
                self._size)  # TODO re_string.Nocopy
        return self._bytes

    def is_resolved(self):
        return self._resolved

    def set_resolved(self):
        self._resolved = True

    def is_resolvedPointers(self):
        return self._resolvedPointers

    def toString(self):
        # print self.fields
        self._fields.sort()
        fieldsString = '[ \n%s ]' % (
            ''.join([field.toString('\t') for field in self._fields]))
        info = 'resolved:%s SIG:%s size:%d' % (
            self.is_resolved(), self.getSignature(text=True), len(self))
        if len(self.getPointerFields()) != 0:
            info += ' resolvedPointers:%s' % (self.is_resolvedPointers())
        ctypes_def = '''
class %s(ctypes.Structure):  # %s
  _fields_ = %s

''' % (self.get_name(), info, fieldsString)
        return ctypes_def

    def __contains__(self, other):
        if isinstance(other, numbers.Number):
            # test vaddr in struct instance len
            if self._vaddr <= other <= self._vaddr + len(self):
                return True
            return False
        else:
            raise NotImplementedError(type(other))

    def __getitem__(self, i):
        return self._fields[i]

    def __len__(self):
        return int(self._size)

    def __cmp__(self, other):
        if not isinstance(other, AnonymousStructInstance):
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
            self.setName(None)
        return

    def __str__(self):
        return 'struct_%x' % (self._vaddr)


class ReversedType(ctypes.Structure):

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
    def toString(self):
        fieldsStrings = []
        for attrname, attrtyp in self.get_fields():  # model
            # FIXME need ctypesutils.
            if self.ctypes.is_pointer_type(
                    attrtyp) and not self.ctypes.is_pointer_to_void_type(attrtyp):
                fieldsStrings.append(
                    '(%s, ctypes.POINTER(%s) ),\n' %
                    (attrname, attrtyp._type_.__name__))
            else:  # pointers not in the heap.
                fieldsStrings.append(
                    '(%s, %s ),\n' %
                    (attrname, attrtyp.__name__))
        fieldsString = '[ \n%s ]' % (''.join(fieldsStrings))

        info = 'size:%d' % (self.ctypes.sizeof(self))
        ctypes_def = '''
class %s(ctypes.Structure):  # %s
  _fields_ = %s

''' % (self.__name__, info, fieldsString)
        return ctypes_def

