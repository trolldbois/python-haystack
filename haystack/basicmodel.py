#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This module is the main aspect of haystack.
This specific plugin handles basic types.

"""

import logging
import numbers
import sys

from haystack import utils
from haystack import constraints
from haystack.utils import get_subtype

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('basicmodel')


class LoadableMembers(object):

    """
    This is the main class, to be inherited by all ctypes structure.
    It adds a generic validation framework, based on simple assertion,
    and on more complex constraint on members values.

    """
    MAX_CSTRING_SIZE = 1024
    # contraints on values TODO rename _expectedValues_
    expectedValues = dict()

    def getFields(self):
        """         Iterate over the fields and types of this structure, including inherited ones."""
        return type(self).getFields()

    @classmethod
    def getFieldType(cls, fieldname):
        """ return a members type"""
        ret = [(n, fieldtype)
               for n, fieldtype in cls.getFields() if n == fieldname]
        if len(ret) != 1:
            raise TypeError('No such field name %s in %s' % (fieldname, cls))
        return ret[0][1]

    @classmethod
    def getFields(cls):
        mro = cls.mro()[:-3]  # cut Structure, _CData and object
        mro.reverse()
        me = mro.pop(-1)
        #ret = list()
        for typ in mro:  # firsts are first, cls is in here in [-1]
            if not hasattr(typ, '_fields_'):
                continue
            for name, vtyp in typ.getFields():
                yield (name, vtyp)
                #ret.append((name, vtyp))
        # print mines.
        for f in me._fields_:
            yield (f[0], f[1])
            # ret.append((f[0],f[1]))

        raise StopIteration
        # return ret

    def get_orig_addr(self, mappings):
        """ returns the vaddr of this instance."""
        import ctypes
        haystack_addr = ctypes.addressof(self)
        m = mappings._get_mmap_for_haystack_addr(haystack_addr)
        return m.ptov(haystack_addr)

    def isValid(self, mappings):
        """
        Checks if each members has coherent data

        For each Field, check on of the three case,
            a) basic types (check for expectedValues),
                if field as some expected values in expectedValues
                     check field value against expectedValues[fieldname]
                     if False, return False, else continue

            b) struct(check isValid)
                check if the inner struct isValid()
                if False, return False, else continue

            c) is an array , recurse validation

            d) Pointer(check valid_address or expectedValues is None == NULL )
                if field as some expected values in expectedValues
                    ( None or 0 ) are the only valid options to design NULL pointers
                     check field get_pointee_address() value against expectedValues[fieldname] // if NULL
                            if True(address is NULL and it's a valid value), continue
                     check get_pointee_address against is_valid_address()
                            if False, return False, else continue
        """
        valid = self._isValid(mappings)
        log.debug('-- <%s> isValid = %s' % (self.__class__.__name__, valid))
        return valid

    def _isValid(self, mappings):
        """ real implementation.    check expectedValues first, then the other fields """
        log.debug(' -- <%s> isValid --' % (self.__class__.__name__))
        _fieldsTuple = self.getFields()
        myfields = dict(_fieldsTuple)
        done = []
        # check expectedValues first
        for attrname, expected in self.expectedValues.iteritems():
            done.append(attrname)
            log.debug(' +++ %s %s ' % (attrname, expected))
            attrtype = myfields[attrname]
            attr = getattr(self, attrname)
            if expected is constraints.IgnoreMember:
                continue
            if not self._isValidAttr(attr, attrname, attrtype, mappings):
                return False
        # check the rest for validation
        todo = [(name, typ)
                for name, typ in self.getFields() if name not in done]
        for attrname, attrtype, in todo:
            attr = getattr(self, attrname)
            if not self._isValidAttr(attr, attrname, attrtype, mappings):
                return False
        # validation done
        return True

    def _isValidAttr(self, attr, attrname, attrtype, mappings):
        """ Validation of a single member """
        import ctypes
        # a)
        log.debug('valid: %s, %s' % (attrname, attrtype))
        if ctypes.is_basic_type(attrtype):
            if attrname in self.expectedValues:
                if attr not in self.expectedValues[attrname]:
                    log.debug(
                        'basicType: %s %s %s bad value not in self.expectedValues[attrname]:' %
                        (attrname, attrtype, repr(attr)))
                    return False
            log.debug(
                'basicType: %s %s %s ok' %
                (attrname, attrtype, repr(attr)))
            return True
        # b)
        elif ctypes.is_struct_type(attrtype) or ctypes.is_union_type(attrtype):
            # do i need to load it first ? becaus it should be memcopied with
            # the super()..
            if not attr.isValid(mappings):
                log.debug(
                    'structType: %s %s %s isValid FALSE' %
                    (attrname, attrtype, repr(attr)))
                return False
            log.debug(
                'structType: %s %s %s isValid TRUE' %
                (attrname, attrtype, repr(attr)))
            return True
        # c)
        elif ctypes.is_array_of_basic_type(attrtype):
            if attrname in self.expectedValues:
                if attr not in self.expectedValues[attrname]:
                    log.debug(
                        'basicArray: %s %s %s - bad value not in self.expectedValues[attrname]:' %
                        (attrname, attrtype, type(attr)))
                    return False
            log.debug(
                'basicArray: %s is arraytype %s we decided it was valid',
                attrname,
                type(attr))
            return True
        # d)
        elif ctypes.is_array_type(attrtype):
            log.debug('array: %s is arraytype %s recurse validate' % (attrname,
                                                                      repr(attr)))
            attrLen = len(attr)
            if attrLen == 0:
                return True
            elType = type(attr[0])
            for i in range(0, attrLen):
                # FIXME BUG DOES NOT WORK - offsetof("%s[%d]") is called,
                # and %s exists, not %s[%d]
                if not self._isValidAttr(attr[i], "%s[%d]" % (attrname, i), elType,
                                         mappings):
                    return False
            return True
        # e)
        elif ctypes.is_cstring_type(attrtype):
            myaddress = utils.get_pointee_address(attr.ptr)
            if attrname in self.expectedValues:
                # test if NULL is an option
                if not bool(myaddress):
                    if not ((None in self.expectedValues[attrname]) or
                            (0 in self.expectedValues[attrname])):
                        log.debug('str: %s %s %s isNULL - NOT EXPECTED' % (
                            attrname, attrtype, repr(attr)))
                        return False
                    log.debug('str: %s %s %s isNULL - OK' % (attrname, attrtype,
                                                             repr(attr)))
                    # e.1)
                    return True
            if (myaddress != 0 and
                    not mappings.is_valid_address_value(myaddress)):
                log.debug('str: %s %s %s 0x%lx INVALID' % (attrname, attrtype,
                                                           repr(attr), myaddress))
                # e.2)
                return False
            log.debug('str: %s %s %s is at 0x%lx OK' % (attrname, attrtype,
                                                        repr(attr), myaddress))
            # e.3)
            return True
        # f)
        elif ctypes.is_pointer_type(attrtype):
            myaddress = utils.get_pointee_address(attr)
            if attrname in self.expectedValues:
                # test if NULL is an option
                log.debug('ctypes.is_pointer_type: bool(attr):%s attr:%s' % (
                    bool(attr), attr))
                if not bool(myaddress):
                    if not ((None in self.expectedValues[attrname]) or
                            (0 in self.expectedValues[attrname])):
                        log.debug('ptr: %s %s %s isNULL - NOT EXPECTED' % (
                            attrname, attrtype, repr(attr)))
                        # f.1) expectedValues specifies NULL to be invalid
                        return False
                    log.debug('ptr: %s %s %s isNULL - OK' % (attrname, attrtype,
                                                             repr(attr)))
                    # f.2) expectedValues specifies NULL to be valid
                    return True
            _attrType = None
            if (ctypes.is_pointer_to_void_type(attrtype) or
                    ctypes.is_function_type(attrtype)):
                log.debug(
                    'Its a simple type. Checking mappings only. attr=%s' %
                    (attr))
                if (myaddress != 0 and
                        not mappings.is_valid_address_value(myaddress)):
                    log.debug('voidptr: %s %s %s 0x%lx INVALID simple pointer' % (
                        attrname, attrtype, repr(attr), myaddress))
                    # f.3) address must be valid, no type requirement
                    return False
            else:
                # test valid address mapping
                _attrType = get_subtype(attrtype)
            if (myaddress != 0 and
                    not mappings.is_valid_address(attr, _attrType)):
                log.debug('ptr: %s %s %s 0x%lx INVALID' % (attrname, attrtype,
                                                           repr(attr), utils.get_pointee_address(attr)))
                # f.4) its a pointer, but not valid in our mappings for this
                # pointee type.
                return False
            log.debug('ptr: name:%s repr:%s address:0x%lx OK' % (attrname,
                                                                 repr(attr), utils.get_pointee_address(attr)))
            # f.5) null is accepted by default
            return True
        # g)
        log.error('What type are You ?: %s/%s' % (attrname, attrtype))
        return True

    def _isLoadableMember(self, attr, attrname, attrtype):
        """
        Check if the member is loadable.
        A c_void_p cannot be load generically, You have to take care of that.

        (Pointers with valid address space value
        AND (pointee is a struct type OR pointee is a union type)
        ) OR struct type OR union type
        """
        ctypes = self._mappings_.config.ctypes
        return ((bool(attr) and not ctypes.is_pointer_to_void_type(attrtype)))
        # return ( (bool(attr) and
        #    (ctypes.is_pointer_to_struct_type(attrtype) or
        #     ctypes.is_pointer_to_union_type(attrtype) or
        #     ctypes.is_pointer_to_basic_type(attrtype) or
        #     ctypes.is_pointer_to_array_type(attrtype)
        #    )) or
        #    ctypes.is_union_type(attrtype) or ctypes.is_struct_type(attrtype) or
        #    ctypes.is_cstring_type(attrtype) or
        #    (ctypes.is_array_type(attrtype) and not ctypes.is_array_of_basic_type(attrtype)))
        # should we iterate on Basictypes ? no

    def loadMembers(self, mappings, maxDepth):
        """
        The validity of the members will be assessed.
        Each members that can be ( structures, pointers), will be evaluated for
        validity and loaded recursively.

        :param mappings: list of memoryMappings for the process.
        :param maxDepth: limitation of depth after which the loading/validation
        will stop and return results.

        @returns True if everything has been loaded, False if something went
        wrong.
        """
        self._mappings_ = mappings
        if maxDepth <= 0:
            log.debug('Maximum depth reach. Not loading any deeper members.')
            log.debug('Struct partially LOADED. %s not loaded' % (
                self.__class__.__name__))
            return True
        maxDepth -= 1
        if not self.isValid(mappings):
            return False
        log.debug('- <%s> do loadMembers -' % (self.__class__.__name__))
        # go through all members. if they are pointers AND not null AND in
        # valid memorymapping AND a struct type, load them as struct pointers
        for attrname, attrtype in self.getFields():
            attr = getattr(self, attrname)
            # shorcut ignores
            if attrname in self.expectedValues:
                # shortcut
                if self.expectedValues[attrname] is constraints.IgnoreMember:
                    return True
            try:
                if not self._loadMember(attr, attrname, attrtype, mappings,
                                        maxDepth):
                    return False
            except ValueError as e:
                log.error('maxDepth was %d' % maxDepth)
                raise

        log.debug('- <%s> END loadMembers -' % (self.__class__.__name__))
        return True

    def _loadMember(self, attr, attrname, attrtype, mappings, maxDepth):
        ctypes = self._mappings_.config.ctypes
        # skip static void_p data members
        if not self._isLoadableMember(attr, attrname, attrtype):
            log.debug("%s %s not loadable bool(attr) = %s" % (attrname, attrtype,
                                                              bool(attr)))
            return True
        # load it, fields are valid
        elif ctypes.is_struct_type(attrtype) or ctypes.is_union_type(attrtype):
            # its an embedded record. Bytes are already loaded.
            offset = utils.offsetof(type(self), attrname)
            log.debug('st: %s %s is STRUCT at @%x' % (attrname, attrtype,
                                                      self._orig_address_ + offset))
            # TODO pydoc for impl.
            attr._orig_address_ = self._orig_address_ + offset
            attr._mappings = mappings
            if not attr.loadMembers(mappings, maxDepth - 1):
                log.debug(
                    "st: %s %s not valid, error while loading inner struct" %
                    (attrname, attrtype))
                return False
            log.debug("st: %s %s inner struct LOADED " % (attrname, attrtype))
            return True
        elif ctypes.is_array_of_basic_type(attrtype):
            return True
        elif ctypes.is_array_type(attrtype):
            log.debug('a: %s is arraytype %s recurse load' % (attrname,
                                                              repr(attr)))
            attrLen = len(attr)
            if attrLen == 0:
                return True
            elType = type(attr[0])
            for i in range(0, attrLen):
                # FIXME BUG DOES NOT WORK
                # offsetof("%s[%d]") is called, and %s exists, not %s[%d]
                # if not self._loadMember(attr[i], "%s[%d]"%(attrname,i),
                # elType, mappings, maxDepth):
                if not self._loadMember(
                        attr[i], attrname, elType, mappings, maxDepth):
                    return False
            return True
        # we have PointerType here . Basic or complex
        # exception cases
        elif ctypes.is_function_type(attrtype):
            pass
            # FIXME
        elif ctypes.is_cstring_type(attrtype):
            # can't use basic c_char_p because we can't load in foreign memory
            # FIXME, you need to keep a ref to this ctring if
            # your want _mappings_ to exists
            # or just mandate mappings in toString
            attr_obj_address = utils.get_pointee_address(attr.ptr)
            if not bool(attr_obj_address):
                log.debug('%s %s is a CString, the pointer is null (validation '
                          'must have occurred earlier)' % (attrname, attr))
                return True
            memoryMap = mappings.is_valid_address_value(attr_obj_address)
            if not memoryMap:
                log.warning('Error on addr while fetching a CString.'
                            'should not happen')
                return False
            ref = mappings.getRef(ctypes.CString, attr_obj_address)
            if ref:
                log.debug("%s %s loading from references cache %s/0x%lx" % (attrname,
                                                                            attr, ctypes.CString, attr_obj_address))
                return True
            max_size = min(
                self.MAX_CSTRING_SIZE,
                memoryMap.end -
                attr_obj_address)
            log.debug('%s %s is defined as a CString, loading %d bytes from 0x%lx '
                      'is_valid_address %s' % (attrname, attr, max_size, attr_obj_address,
                                               mappings.is_valid_address_value(attr_obj_address)))
            txt, truncated = memoryMap.readCString(attr_obj_address, max_size)
            if truncated:
                log.warning(
                    'buffer size was too small for this CString: %d' %
                    (max_size))

            # that will SEGFAULT attr.string = txt - instead keepRef to String
            mappings.keepRef(txt, ctypes.CString, attr_obj_address)
            log.debug(
                'kept CString ref for "%s" at @%x' %
                (txt, attr_obj_address))
            return True
        # not functionType, it's not loadable
        elif ctypes.is_pointer_type(attrtype):
            _attrType = get_subtype(attrtype)
            attr_obj_address = utils.get_pointee_address(attr)
            ####
            # memcpy and save objet ref + pointer in attr
            # we know the field is considered valid, so if it's not in
            # memory_space, we can ignore it
            memoryMap = mappings.is_valid_address(attr, _attrType)
            if(not memoryMap):
                # big BUG Badaboum, why did pointer changed validity/value ?
                log.warning(
                    "%s %s not loadable 0x%lx but VALID " %
                    (attrname, attr, attr_obj_address))
                return True

            ref = mappings.getRef(_attrType, attr_obj_address)
            if ref:
                log.debug(
                    "%s %s loading from references cache %s/0x%lx" %
                    (attrname, attr, _attrType, attr_obj_address))
                # DO NOT CHANGE STUFF SOUPID attr.contents = ref. attr.contents
                # will SEGFAULT
                return True
            log.debug(
                "%s %s loading from 0x%lx (is_valid_address: %s)" %
                (attrname, attr, attr_obj_address, memoryMap))
            # Read the struct in memory and make a copy to play with.
            # DO NOT COPY THE STRUCT, we have a working readStruct for that...
            # ERRROR
            # attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address,
            # _attrType ))
            contents = memoryMap.readStruct(attr_obj_address, _attrType)

            # save that validated and loaded ref and original addr so we dont
            # need to recopy it later
            mappings.keepRef(contents, _attrType, attr_obj_address)
            log.debug(
                "keepRef %s.%s @%x" %
                (_attrType, attrname, attr_obj_address))
            log.debug(
                "%s %s loaded memcopy from 0x%lx to 0x%lx" %
                (attrname,
                 attr,
                 attr_obj_address,
                 (utils.get_pointee_address(attr))))
            # recursive validation checks on new struct
            if not bool(attr):
                log.warning(
                    'Member %s is null after copy: %s' %
                    (attrname, attr))
                return True
            # go and load the pointed struct members recursively
            subtype = utils.get_subtype(attrtype)
            if (ctypes.is_basic_type(subtype) or
                    ctypes.is_array_of_basic_type(subtype)):
                # do nothing
                return True
            elif (ctypes.is_array_type(subtype) or
                  ctypes.is_pointer_type(subtype)):
                return self._loadMember(
                    contents, 'pointee', subtype, mappings, maxDepth - 1)

            if not contents.loadMembers(mappings, maxDepth - 1):
                log.debug('member %s was not loaded' % (attrname))
                # invalidate the cache ref.
                mappings.delRef(_attrType, attr_obj_address)
                return False
            return True
        # TATAFN
        return True

    def __str__(self):
        """Print the direct members values. Never tries to recurse."""
        import ctypes
        if hasattr(self, '_orig_address_'):
            s = "# <%s at @%x>\n" % (
                self.__class__.__name__, self._orig_address_)
        else:
            s = "# <%s at @???>\n" % (self.__class__.__name__)
        # we need to ensure _mappings_ is defined in all children.
        for field, attrtype in self.getFields():
            attr = getattr(self, field)
            if ctypes.is_basic_type(attrtype):
                # basic type, ctypes or python
                s += '%s : %s, \n' % (field, repr(attr))
            elif (ctypes.is_struct_type(attrtype) or
                  ctypes.is_union_type(attrtype)):
                # you can print a inner struct content
                s += '%s (@0x%lx) : {\t%s}\n' % (field,
                                                 ctypes.addressof(attr),
                                                 attr)
            elif ctypes.is_function_type(attrtype):
                # only print address in target space
                s += '%s (@0x%lx) : 0x%lx (FIELD NOT LOADED: function type)\n' % (
                    field, ctypes.addressof(attr),
                    utils.get_pointee_address(attr))
            elif ctypes.is_array_of_basic_type(attrtype):
                try:
                    s += '%s (@0x%lx) : %s\n' % (field, ctypes.addressof(attr),
                                                 repr(utils.array2bytes(attr)))
                except IndexError as e:
                    log.error('error while reading %s %s' % (repr(attr),
                                                             type(attr)))
                    # FIXME
            elif ctypes.is_array_type(attrtype):
                # array of something else than int
                s += '%s (@0x%lx)    :[' % (field, ctypes.addressof(attr))
                s += ','.join(["%s" % (val) for val in attr])
                s += '],\n'
            elif ctypes.is_cstring_type(attrtype):
                # only print address/null
                s += '%s (@0x%lx) : 0x%lx\n' % (field, ctypes.addressof(attr),
                                                utils.get_pointee_address(attr.ptr))
            elif ctypes.is_pointer_type(attrtype):  # and
                # not ctypes.is_pointer_to_void_type(attrtype)):
                # do not recurse.
                if attr is None:
                    attr = 0
                s += '%s (@0x%lx) : 0x%lx\n' % (field, ctypes.addressof(attr),
                                                utils.get_pointee_address(attr))
            elif (isinstance(attr, long)) or (isinstance(attr, int)):
                s += '%s : %s\n' % (field, hex(attr))
            else:
                s += '%s : %s\n' % (field, repr(attr))
        return s

    def __repr__(self):
        if hasattr(self, '_orig_address_'):
            return "# <%s at @%x>\n" % (self.__class__.__name__,
                                        self._orig_address_)
        else:
            return "# <%s at @???>\n" % (self.__class__.__name__)
