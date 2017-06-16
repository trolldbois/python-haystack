#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import numbers
import sys

from haystack.outputters import Outputter
from haystack import types
from haystack import basicmodel


log = logging.getLogger('python')


class PythonOutputter(Outputter):

    """ Parse a self._ctypes structure and outputs a pure python object."""

    def parse(self, obj, prefix='', depth=50):
        """
        Returns a Plain Old python object as a perfect copy of this self._ctypes object.
        array would be lists, pointers, inner allocators, and circular
        reference should be handled nicely.
        """
        # get self class.
        try:
            obj_module_name = obj.__class__.__module__
            obj_class_name = obj.__class__.__name__
            try:
                obj_module = self._model.get_pythoned_module(obj_module_name)
            except KeyError:
                # FIXME - ctypes modules should not be in sys.modules. what about reloading?
                self._model.build_python_class_clones(sys.modules[obj_module_name])
                obj_module = self._model.get_pythoned_module(obj_module_name)
            my_class = getattr(obj_module, "%s_py" % obj_class_name)
        except AttributeError as e:
            log.warning('did you forget to register your python allocators ?')
            raise
        my_self = my_class()
        my_address = self._ctypes.addressof(obj)
        # keep ref of the POPO too.
        if self._memory_handler.hasRef(my_class, my_address):
            return self._memory_handler.getRef(my_class, my_address)
        # save our POPO in a partially resolved state, to keep from loops.
        self._memory_handler.keepRef(my_self, my_class, my_address)
        for field, typ in basicmodel.get_fields(obj):
            attr = getattr(obj, field)
            try:
                member = self._attrToPyObject(attr, field, typ)
            except NameError as e:
                raise NameError('%s %s\n%s' % (field, typ, e))

            setattr(my_self, field, member)
        # save the original type (me) and the field
        setattr(my_self, '_ctype_', type(obj))
        return my_self

    def _attrToPyObject(self, attr, field, attrtype):
        if self._ctypes.is_basic_type(attrtype):
            if self._ctypes.is_basic_ctype(type(attr)):
                obj = attr.value
            else:
                obj = attr
        elif self._ctypes.is_struct_type(attrtype) or self._ctypes.is_union_type(attrtype):
            attr._mappings_ = self._memory_handler
            obj = self.parse(attr)
        elif self._ctypes.is_array_of_basic_type(attrtype):
            # return a list of int, float, or a char[] to str
            obj = self._utils.ctypes_to_python_array(attr)
        elif self._ctypes.is_array_type(attrtype):
            # array of something else than int/byte
            obj = []
            eltyp = type(attr[0])
            for i in range(0, len(attr)):
                obj.append(self._attrToPyObject(attr[i], i, eltyp))
        elif self._ctypes.is_cstring_type(attrtype):
            obj = self._memory_handler.getRef(
                self._ctypes.CString,
                self._utils.get_pointee_address(
                    attr.ptr))
        elif self._ctypes.is_function_type(attrtype):
            obj = repr(attr)
        elif self._ctypes.is_pointer_type(attrtype):
            # get the cached Value of the LP.
            _subtype = self._utils.get_subtype(attrtype)
            _address = self._utils.get_pointee_address(attr)
            #if field == 'ProcessHeaps':
            #    import code
            #    code.interact(local=locals())
            if _address == 0:
                # Null pointer
                obj = None
            elif self._ctypes.is_pointer_to_void_type(attrtype):
                # TODO: make a prototype for c_void_p loading
                # void types a rereturned as None
                obj = None
            elif self._ctypes.is_array_of_basic_type(attrtype):
                log.error('basic Type array - %s' % (field))
                obj = 'BasicType array'
            else:
                # FIXME we should NOT recurse
                # get the cached Value of the LP.
                cache = self._memory_handler.getRef(_subtype, _address)
                if cache is not None:  # struct, union...
                    obj = self._attrToPyObject(cache, field, _subtype)
                else:
                    # you got here because your pointer is not loaded:
                    #  did you ignore it in expectedValues ?
                    #  is it in the middle of a struct ?
                    #  is that a linked list ?
                    #  is it a invalid instance ?
                    log.debug('Pointer for field:%s %s/%s not in cache '
                              '0x%x' % (field, attrtype, self._utils.get_subtype(attrtype),
                                        _address))
                    return (None, None)
        elif isinstance(attr, numbers.Number):
            # case for int, long. But needs to be after c_void_p pointers case
            obj = attr
        else:
            log.error('toPyObj default to return attr %s' % (type(attr)))
            obj = attr
        return obj


def json_encode_pyobj(obj):
    if hasattr(obj, '_ctype_'):
        return obj.__dict__
    elif type(obj).__name__ == 'int':
        log.warning('found an int')
        return str(obj)
    else:
        return obj


class pyObj(object):

    """
    Base class for a plain old python object.
    all haystack/ctypes classes will be translated in this format before pickling.

    Operations :
        - toString(self, prefix):    print a nicely formatted data structure
                :param prefix: str to insert before each line (\t after that)
        - findCtypes(self) : checks if a self._ctypes is to be found somewhere is the object.
                                            Useful to check if the object can be pickled.
    """

    def toString(self, prefix='', maxDepth=10):
        if maxDepth < 0:
            return '#(- not printed by Excessive recursion - )'
        s = '{\n'
        if hasattr(self, '_ctype_'):
            items = [n for n, t in basicmodel.get_record_type_fields(self._ctype_)]
        else:
            log.warning('no _ctype_')
            items = [n for n in self.__dict__.keys() if n != '_ctype_']
        for attrname in items:
            attr = getattr(self, attrname)
            typ = type(attr)
            s += "%s%s: %s\n" % (prefix,
                                 attrname,
                                 self._attrToString(
                                     attr,
                                     attrname,
                                     typ,
                                     prefix + '\t',
                                     maxDepth=maxDepth - 1))
        s += '}'
        return s

    def _attrToString(self, attr, attrname, typ, prefix, maxDepth):
        s = ''
        if isinstance(attr, tuple) or isinstance(attr, list):
            for i in xrange(0, len(attr)):
                s += '%s,' % (self._attrToString(attr[i],
                                                 i,
                                                 None,
                                                 prefix + '\t',
                                                 maxDepth))
            s = "[%s]," % (s)
        elif not hasattr(attr, '__dict__'):
            s = '%s,' % (repr(attr))
        elif isinstance(attr, pyObj):
            s = '%s,' % (attr.toString(prefix, maxDepth))
        else:
            s = '%s,' % (repr(attr))
        return s

    def __len__(self):
        return self._len_

    def findCtypes(self, cache=None):
        """ recurse on members to check for self._ctypes object. """
        if cache is None:
            cache = set()
        ret = False
        for attrname, attr in self.__dict__.items():
            if id(attr) in cache:  # do not recurse in already parsed
                continue
            # ignore _ctype_, it's a ctype class type, we know that.
            if attrname == '_ctype_':
                cache.add(id(attr))
                continue
            typ = type(attr)
            attr = getattr(self, attrname)
            log.debug('findCtypes on attr %s' % attrname)
            if self._attrFindCtypes(attr, attrname, typ, cache):
                log.warning('Found a self._ctypes in %s' % (attrname))
                ret = True
        return ret

    def _attrFindCtypes(self, attr, attrname, typ, cache):
        ret = False
        cache.add(id(attr))
        if hasattr(attr, '_ctype_'):  # a pyobj
            return attr.findCtypes(cache)
        elif isinstance(attr, tuple) or isinstance(attr, list):
            for el in attr:
                if self._attrFindCtypes(el, 'element', None, cache):
                    log.warning('Found a self._ctypes in array/tuple')
                    return True
        elif types.is_ctypes_instance(attr):
            log.warning('Found a self._ctypes in self %s' % (attr))
            return True
        else:  # int, long, str ...
            ret = False
        return ret

    def __iter__(self):
        """ iterate on a instance's type's _fields_ members following the original type field order """
        for k, typ in basicmodel.get_fields(self._ctype_):
            v = getattr(self, k)
            yield (k, v, typ)
        pass

    # the python cannot contain a ref to a ctypes
    def __getstate__(self):
        d = self.__dict__.copy()
        if '_ctype_' in d:
            d['_ctype_'] = d['_ctype_'].__class__.__name__
        return d

    def __reduce__(self):
        """Explains how to rebuild this class once pickled."""
        state = self.__dict__.copy()
        if '_ctype_' in state:
            state['_ctype_'] = state['_ctype_'].__class__.__name__
        name = self.__class__.__name__
        modulename = self.__module__
        return (_pyObjBuilder(), # __call__
                (modulename, name), # arg for builder
                state
                )


class _pyObjBuilder:
    """Builder of pickled instance of pyObj into properly named POPO"""
    def __call__(self, modulename, classname):
        # make a simple object which has no complex __init__ (this one will do)
        obj = pyObj()
        # class = getattr(containing_class, class_name)
        # kpy = type('%s.%s' % (modulename, classname), (pyObj,), {})
        kpy = type(classname, (pyObj,), {})
        obj.__class__ = kpy
        return obj


def findCtypesInPyObj(memory_handler, obj):
    """ check function to help in unpickling errors correction """
    if hasattr(obj, 'findCtypes'):
        if obj.findCtypes():
            log.warning('Found a self._ctypes in array/tuple')
            return True
    elif isinstance(obj, tuple) or isinstance(obj, list):
        for el in obj:
            if findCtypesInPyObj(memory_handler, el):
                log.warning('Found a self._ctypes in array/tuple')
                return True
    elif types.is_ctypes_instance(obj):
        return True
    return False
