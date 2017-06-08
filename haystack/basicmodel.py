#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This module is the main aspect of haystack.
This specific plugin handles basic types.

"""

import ctypes
import logging

from haystack import constraints
from haystack import utils
from haystack.abc import interfaces

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('basicmodel')


def get_field_type(record, fieldname):
    """ return a members type"""
    ret = [(n, fieldtype)
           for n, fieldtype in get_fields(record) if n == fieldname]
    if len(ret) != 1:
        raise TypeError('No such field name %s in %s' % (fieldname, record))
    return ret[0][1]

def get_fields(record):
    if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
        raise TypeError('Feed me a ctypes record instance. Not: %s'% record)
    return get_record_type_fields(type(record))

def get_record_type_fields(record_type):
    if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
        raise TypeError('Feed me a ctypes record type')
    mro = list(record_type.__mro__[:-3]) # cut Structure, _CData and object
    mro.reverse()
    me = mro.pop(-1)
    for typ in mro:  # firsts are first, cls is in here in [-1]
        if not hasattr(typ, '_fields_'):
            continue
        for name, vtyp in get_fields(typ):
            yield (name, vtyp)
    # print mines.
    for f in me._fields_:
        yield (f[0], f[1])
    #raise StopIteration
    return


class CTypesRecordConstraintValidator(interfaces.IRecordConstraintsValidator):
    """
    This is the main class, to be inherited by all ctypes record validators.
    It adds a generic validation framework, based on simple assertion,
    and on more complex constraint on members values.

    FIXME: ConstraintsValidator should be loaded with a memory mapping, not an handler.
    The target platform is different mapping by mapping. (windows heap 32/64)
    """
    MAX_CSTRING_SIZE = 1024

    def __init__(self, memory_handler, my_constraints, target_ctypes=None):
        """

        :param memory_handler: IMemoryHandler
        :param my_constraints: IModuleConstraints
        :param target_ctypes: Ctypes module, could be a different arch.
        :return:
        """
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if my_constraints and not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        if target_ctypes is None:
            target_ctypes = memory_handler.get_target_platform().get_target_ctypes()
        if not hasattr(target_ctypes, 'c_ubyte'):
            raise TypeError("Feed me a target_ctypes as Ctypes modules")
        self._memory_handler = memory_handler
        self._ctypes = target_ctypes
        self._utils = utils.Utils(self._ctypes)
        self._constraints_base = None
        self._constraints_dynamic = None
        if my_constraints is not None:
            self._constraints_base = my_constraints.get_constraints()
            self._constraints_dynamic = my_constraints.get_dynamic_constraints()

    def _get_constraints_for(self, record):
        n = record.__class__.__name__
        if self._constraints_base and n in self._constraints_base:
            return self._constraints_base[n]
        return dict()

    def _get_dynamic_constraints_for(self, record):
        n = record.__class__.__name__
        if self._constraints_dynamic and n in self._constraints_dynamic:
            return self._constraints_dynamic[n]
        return None

    def get_orig_addr(self, record):
        """ returns the vaddr of this instance."""
        haystack_addr = self._ctypes.addressof(record)
        # FIXME test
        m = self._memory_handler.get_mapping_for_address(haystack_addr)
        return m._ptov(haystack_addr)

    def is_valid(self, record):
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
        # FIXME, for now its a debug statement
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a record')
        valid = self._is_valid(record, self._get_constraints_for(record))
        log.debug('-- <%s> isValid = %s', record.__class__.__name__, valid)
        # check dynamic constraints last.
        if valid:
            return self._is_valid_dynamic_constraints(record)
        return False

    def _is_valid_dynamic_constraints(self, record):
        dynamic_constraints = self._get_dynamic_constraints_for(record)
        if dynamic_constraints:
            log.debug("dynamic constraints are %s", dynamic_constraints)
            return dynamic_constraints.is_valid(record)
        return True

    def _is_valid(self, record, record_constraints):
        """ real implementation.    check expectedValues first, then the other fields """
        log.debug(' -- <%s> isValid --', record.__class__.__name__)
        done = []
        # we check constrained field first to stop early if possible
        # then we test the other fields
        log.debug("constraints are on %s", record_constraints)
        _fieldsTuple = get_fields(record)
        myfields = dict(_fieldsTuple)
        for attrname, _constraints in record_constraints.items():
            if attrname not in myfields:
                log.warning('constraint check: field %s does not exists in record for %s',
                            attrname, record.__class__.__name__)
                continue
            done.append(attrname)
            attrtype = myfields[attrname]
            attr = getattr(record, attrname)
            ignore = False
            for expected in _constraints:
                log.debug(' +++ %s %s ', attrname, expected)
                if expected is constraints.IgnoreMember:
                    ignore = True
                    break
            if ignore:
                log.debug('IgnoreMember: %s ', attrname)
                continue
            if not self._is_valid_attr(attr, attrname, attrtype, record_constraints):
                return False
        # check the other fields for validation
        todo = [(name, typ) for name, typ in get_fields(record) if name not in done]
        for attrname, attrtype, in todo:
            attr = getattr(record, attrname)
            if not self._is_valid_attr(attr, attrname, attrtype, record_constraints):
                return False
        # validation done
        return True

    def _is_valid_attr(self, attr, attrname, attrtype, record_constraints):
        """ Validation of a single member """
        # a)
        log.debug('valid: %s, %s' % (attrname, attrtype))
        if self._ctypes.is_basic_type(attrtype):
            if attrname in record_constraints:
                if attr not in record_constraints.get_constraints_for_field(attrname):
                    log.debug(
                        'basicType: %s %s %s bad value not in record_constraints[attrname]:',
                        attrname, attrtype, repr(attr))
                    return False
            log.debug('basicType: %s %s %s ok', attrname, attrtype, repr(attr))
            return True
        # b)
        elif self._ctypes.is_struct_type(attrtype) or self._ctypes.is_union_type(attrtype):
            # do i need to load it first ? because it should be memcopied with
            # the super()..
            if not self.is_valid(attr):
                log.debug('structType: %s %s %s isValid FALSE', attrname, attrtype, repr(attr))
                return False
            log.debug('structType: %s %s %s isValid TRUE', attrname, attrtype, repr(attr))
            return True
        # c)
        elif self._ctypes.is_array_of_basic_type(attrtype):
            if attrname in record_constraints:
                if attr not in record_constraints[attrname]:
                    log.debug(
                        'basicArray: %s %s %s - bad value not in record_constraints[attrname]:',
                        attrname, attrtype, type(attr))
                    return False
            log.debug('basicArray: %s is arraytype %s we decided it was valid', attrname, type(attr))
            return True
        # d)
        elif self._ctypes.is_array_type(attrtype):
            log.debug('array: %s is arraytype %s recurse validate', attrname, repr(attr))
            attrLen = len(attr)
            if attrLen == 0:
                return True
            elType = type(attr[0])
            for i in range(0, attrLen):
                # FIXME BUG DOES NOT WORK - offsetof("%s[%d]") is called,
                # and %s exists, not %s[%d]
                if not self._is_valid_attr(attr[i], "%s[%d]" % (attrname, i), elType, record_constraints):
                    return False
            return True
        # e)
        elif self._ctypes.is_cstring_type(attrtype):
            myaddress = self._utils.get_pointee_address(attr.ptr)
            if attrname in record_constraints:
                # test if NULL is an option
                if not bool(myaddress):
                    if not ((None in record_constraints[attrname]) or (0 in record_constraints[attrname])):
                        log.debug('str: %s %s %s isNULL - NOT EXPECTED', attrname, attrtype, repr(attr))
                        return False
                    log.debug('str: %s %s %s isNULL - OK', attrname, attrtype, repr(attr))
                    # e.1)
                    return True
            if myaddress != 0 and not self.is_valid_address_value(myaddress):
                log.debug('str: %s %s %s 0x%lx INVALID', attrname, attrtype, repr(attr), myaddress)
                # e.2)
                return False
            log.debug('str: %s %s %s is at 0x%lx OK', attrname, attrtype, repr(attr), myaddress)
            # e.3)
            return True
        # f)
        elif self._ctypes.is_pointer_type(attrtype):
            myaddress = self._utils.get_pointee_address(attr)
            #log.debug('_is_valid_attr:0x%x name: %s', myaddress, attrname)
            if attrname in record_constraints:
                # test if NULL is an option
                log.debug('self._ctypes.is_pointer_type: bool(attr):%s attr:%s', bool(attr), attr)
                if not bool(myaddress):
                    if not ((None in record_constraints[attrname]) or (0 in record_constraints[attrname])):
                        log.debug('ptr: %s %s %s isNULL - NOT EXPECTED', attrname, attrtype, repr(attr))
                        # f.1) expectedValues specifies NULL to be invalid
                        return False
                    log.debug('ptr: %s %s %s isNULL - OK', attrname, attrtype, repr(attr))
                    # f.2) expectedValues specifies NULL to be valid
                    return True
            _attrType = None
            if self._ctypes.is_pointer_to_void_type(attrtype) or self._ctypes.is_function_type(attrtype):
                log.debug('Its a simple type. Checking address only. attr=%s', attr)
                if (myaddress != 0 and not self.is_valid_address_value(myaddress)):
                    log.debug('voidptr: %s %s %s 0x%lx INVALID simple pointer',
                              attrname, attrtype, repr(attr), myaddress)
                    # f.3) address must be valid, no type requirement
                    return False
            else:
                # test valid address mapping
                _attrType = self._utils.get_subtype(attrtype)
            if myaddress != 0 and not self.is_valid_address(attr, _attrType):
                log.debug('ptr: %s %s %s 0x%lx INVALID', attrname, attrtype,
                                                           repr(attr), self._utils.get_pointee_address(attr))
                # f.4) its a pointer, but not valid in our _memory_handler for this
                # pointee type.
                return False
            log.debug('ptr: name:%s repr:%s address:0x%lx OK', attrname,
                                                                 repr(attr), self._utils.get_pointee_address(attr))
            # f.5) null is accepted by default
            return True
        # g)
        log.error('What type are You ?: %s/%s' % (attrname, attrtype))
        return True

    def _is_loadable_member(self, attr, attrname, attrtype):
        """
        Check if the member is loadable.
        A c_void_p cannot be load generically, You have to take care of that.

        (Pointers with valid address space value
        AND (pointee is a struct type OR pointee is a union type)
        ) OR struct type OR union type
        """
        return bool(attr) and not self._ctypes.is_pointer_to_void_type(attrtype)

    def load_members(self, record, max_depth):
        """
        The validity of the members will be assessed.
        Each members that can be ( allocators, pointers), will be evaluated for
        validity and loaded recursively.

        :param record: the record to load
        :param max_depth: limitation of depth after which the loading/validation
        will stop and return results.

        @returns True if everything has been loaded, False if something went
        wrong.
        """
        if max_depth <= 0:
            log.debug('Maximum depth reach. Not loading any deeper members.')
            log.debug('Struct partially LOADED. %s not loaded', record.__class__.__name__)
            return True
        if max_depth > 100:
            raise RuntimeError('max_depth')
        max_depth -= 1
        if not self.is_valid(record):
            return False
        log.debug('- <%s> do load_members -', record.__class__.__name__)
        # go through all members. if they are pointers AND not null AND in
        # valid memorymapping AND a struct type, load them as struct pointers
        record_constraints = self._get_constraints_for(record)
        for attrname, attrtype in get_fields(record):
            attr = getattr(record, attrname)
            ignore = False
            # shorcut ignores
            if attrname in record_constraints:
                for _constraint in record_constraints[attrname]:
                    # shortcut
                    if _constraint is constraints.IgnoreMember:
                        ignore = True
                        break
            if ignore:
                continue
            try:
                if not self._load_member(record, attr, attrname, attrtype, record_constraints, max_depth):
                    return False
            except ValueError as e:
                log.error('maxDepth was %d' % max_depth)
                raise
        log.debug('- <%s> END load_members -', record.__class__.__name__)
        return True

    def _load_member(self, record, attr, attrname, attrtype, record_constraints, max_depth):
        # skip static void_p data members
        if not self._is_loadable_member(attr, attrname, attrtype):
            log.debug("%s %s not loadable bool(attr) = %s", attrname, attrtype, bool(attr))
            return True
        # load it, fields are valid
        elif self._ctypes.is_struct_type(attrtype) or self._ctypes.is_union_type(attrtype):
            # its an embedded record. Bytes are already loaded.
            offset = self._utils.offsetof(type(record), attrname)
            log.debug('st: %s %s is STRUCT at @%x', attrname, attrtype, record._orig_address_ + offset)
            # TODO pydoc for impl.
            attr._orig_address_ = record._orig_address_ + offset
            if not self.load_members(attr, max_depth - 1):
                log.debug("st: %s %s not valid, error while loading inner struct", attrname, attrtype)
                return False
            log.debug("st: %s %s inner struct LOADED ", attrname, attrtype)
            return True
        elif self._ctypes.is_array_of_basic_type(attrtype):
            return True
        elif self._ctypes.is_array_type(attrtype):
            log.debug('a: %s is arraytype %s recurse load', attrname, repr(attr))
            attrLen = len(attr)
            if attrLen == 0:
                return True
            elType = type(attr[0])
            for i in range(0, attrLen):
                # FIXME BUG DOES NOT WORK
                # offsetof("%s[%d]") is called, and %s exists, not %s[%d]
                # if not self._load_member(attr[i], "%s[%d]"%(attrname,i),
                # elType, _memory_handler, maxDepth):
                if not self._load_member(record, attr[i], attrname, elType, record_constraints, max_depth):
                    return False
            return True
        # we have PointerType here . Basic or complex
        # exception cases
        elif self._ctypes.is_function_type(attrtype):
            pass
            # FIXME
        elif self._ctypes.is_cstring_type(attrtype):
            # can't use basic c_char_p because we can't load in foreign memory
            # FIXME, you need to keep a ref to this ctring if
            # your want _mappings_ to exists
            # or just mandate _memory_handler in toString
            attr_obj_address = self._utils.get_pointee_address(attr.ptr)
            if not bool(attr_obj_address):
                log.debug('%s %s is a CString, the pointer is null (validation '
                          'must have occurred earlier)', attrname, attr)
                return True
            memoryMap = self.is_valid_address_value(attr_obj_address)
            if not memoryMap:
                log.warning('Error on addr while fetching a CString.'
                            'should not happen')
                return False
            ref = self._memory_handler.getRef(self._ctypes.CString, attr_obj_address)
            if ref is not None:
                log.debug("%s %s loading from references cache %s/0x%lx", attrname,
                                                                            attr, self._ctypes.CString, attr_obj_address)
                return True
            max_size = min(self.MAX_CSTRING_SIZE, memoryMap.end - attr_obj_address)
            log.debug('%s %s is defined as a CString, loading %d bytes from 0x%lx '
                      'is_valid_address %s', attrname, attr, max_size, attr_obj_address,
                                               self.is_valid_address_value(attr_obj_address))
            #txt, truncated = memoryMap.read_cstring(attr_obj_address, max_size)
            # 2015-11-05 FIX #20 - read string or wide char string
            txt, truncated = attr.read_string(memoryMap, attr_obj_address, max_size)
            if truncated:
                log.warning('buffer size was too small for this CString: %d', max_size)

            # that will SEGFAULT attr.string = txt - instead keepRef to String
            self._memory_handler.keepRef(txt, self._ctypes.CString, attr_obj_address)
            log.debug('kept CString ref for "%s" at @%x', txt, attr_obj_address)
            return True
        # not functionType, it's not loadable
        elif self._ctypes.is_pointer_type(attrtype):
            _attrType = self._utils.get_subtype(attrtype)
            attr_obj_address = self._utils.get_pointee_address(attr)
            ####
            # memcpy and save objet ref + pointer in attr
            # we know the field is considered valid, so if it's not in
            # memory_space, we can ignore it
            memoryMap = self.is_valid_address(attr, _attrType)
            if not memoryMap:
                # big BUG Badaboum, why did pointer changed validity/value ?
                log.warning("%s %s not loadable 0x%lx but VALID ", attrname, attr, attr_obj_address)
                return True

            ref = self._memory_handler.getRef(_attrType, attr_obj_address)
            if ref is not None:
                log.debug("%s %s loading from references cache %s/0x%lx", attrname, attr, _attrType, attr_obj_address)
                # DO NOT CHANGE STUFF SOUPID attr.contents = ref. attr.contents
                # will SEGFAULT
                return True
            log.debug("%s %s loading from 0x%lx (is_valid_address: %s)", attrname, attr, attr_obj_address, memoryMap)
            # Read the struct in memory and make a copy to play with.
            # DO NOT COPY THE STRUCT, we have a working readStruct for that...
            # ERRROR
            # attr.contents=_attrType.from_buffer_copy(memoryMap.readStruct(attr_obj_address,
            # _attrType ))
            contents = memoryMap.read_struct(attr_obj_address, _attrType)

            # save that validated and loaded ref and original addr so we dont
            # need to recopy it later
            self._memory_handler.keepRef(contents, _attrType, attr_obj_address)
            log.debug("keepRef %s.%s @%x", _attrType, attrname, attr_obj_address)
            log.debug(
                "%s %s loaded memcopy from 0x%lx to 0x%lx",
                attrname,
                attr,
                attr_obj_address,
                self._utils.get_pointee_address(attr))
            # recursive validation checks on new struct
            if not bool(attr):
                log.warning('Member %s is null after copy: %s', attrname, attr)
                return True
            # go and load the pointed struct members recursively
            subtype = self._utils.get_subtype(attrtype)
            if self._ctypes.is_basic_type(subtype) or self._ctypes.is_array_of_basic_type(subtype):
                # do nothing
                return True
            elif self._ctypes.is_array_type(subtype) or self._ctypes.is_pointer_type(subtype):
                # FIXME
                return self._load_member(record, contents, 'pointee', subtype, record_constraints, max_depth - 1)
            log.debug('d: %d load_members recursively on pointer %s' % (max_depth, attrname))
            if not self.load_members(contents, max_depth - 1):
                log.debug('member %s was not loaded' % attrname)
                # invalidate the cache ref.
                self._memory_handler.delRef(_attrType, attr_obj_address)
                return False
            return True
        # TATAFN
        return True

    def is_valid_address(self, obj, structType=None):
        """
        :param obj: the obj to evaluate.
        :param structType: the object's type, so the size could be taken in consideration.

        Returns False if the object address is NULL.
        Returns False if the object address is not in a mapping.

        Returns the mapping in which the object stands otherwise.
        """
        # check for null pointers
        addr = self._utils.get_pointee_address(obj)
        if addr == 0:
            return False
        return self.is_valid_address_value(addr, structType)

    def is_valid_address_value(self, addr, structType=None):
        """
        :param addr: the address to evaluate.
        :param structType: the object's type, so the size could be taken in consideration.

        Returns False if the object address is NULL.
        Returns False if the object address is not in a mapping.
        Returns False if the object overflows the mapping.

        Returns the mapping in which the address stands otherwise.
        """
        m = self._memory_handler.get_mapping_for_address(addr)
        log.debug('is_valid_address_value = %x %s' % (addr, m))
        if m:
            if structType is not None:
                s = self._ctypes.sizeof(structType)
                if (addr + s) < m.start or (addr + s) > m.end:
                    return False
            return m
        return False

    def __str__(self):
        return "<CTypesRecordConstraintValidator>"

'''
    def __str__(self):
        """Print the direct members values. Never tries to recurse."""
        target_ctypes = self._memory_handler.get_target_platform().get_target_ctypes()
        utils = self._memory_handler.get_ctypes_utils()
        if hasattr(self, '_orig_address_'):
            s = "# <%s at @%x>\n" % (
                self.__class__.__name__, self._orig_address_)
        else:
            s = "# <%s at @???>\n" % (self.__class__.__name__)
        # we need to ensure _mappings_ is defined in all children.
        for field, attrtype in self.get_fields():
            attr = getattr(self, field)
            if self._ctypes.is_basic_type(attrtype):
                # basic type, target_ctypes or python
                s += '%s : %s, \n' % (field, repr(attr))
            elif (self._ctypes.is_struct_type(attrtype) or
                  self._ctypes.is_union_type(attrtype)):
                # you can print a inner struct content
                s += '%s (@0x%lx) : {\t%s}\n' % (field,
                                                 self._ctypes.addressof(attr),
                                                 attr)
            elif self._ctypes.is_function_type(attrtype):
                # only print address in target space
                s += '%s (@0x%lx) : 0x%lx (FIELD NOT LOADED: function type)\n' % (
                    field, self._ctypes.addressof(attr),
                    utils.get_pointee_address(attr))
            elif self._ctypes.is_array_of_basic_type(attrtype):
                try:
                    s += '%s (@0x%lx) : %s\n' % (field, self._ctypes.addressof(attr),
                                                 repr(utils.array2bytes(attr)))
                except IndexError as e:
                    log.error('error while reading %s %s' % (repr(attr),
                                                             type(attr)))
                    # FIXME
            elif self._ctypes.is_array_type(attrtype):
                # array of something else than int
                s += '%s (@0x%lx)    :[' % (field, self._ctypes.addressof(attr))
                s += ','.join(["%s" % val for val in attr])
                s += '],\n'
            elif self._ctypes.is_cstring_type(attrtype):
                # only print address/null
                s += '%s : 0x%lx\n' % (field,
                                                utils.get_pointee_address(attr.ptr))
            elif self._ctypes.is_pointer_type(attrtype):  # and
                # not self._ctypes.is_pointer_to_void_type(attrtype)):
                # do not recurse.
                if attr is None:
                    attr = 0
                    s += '%s : 0x0\n' % field
                else:
                    print attr, type(attr), attrtype
                    s += '%s : 0x%lx\n' % (field, utils.get_pointee_address(attr))
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


'''
