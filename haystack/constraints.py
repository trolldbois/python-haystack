#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This module holds some basic constraint class for the Haystack model.
"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ConfigParser
import logging
import sys

import os
import re

log = logging.getLogger('constraints')

from haystack.abc import interfaces


class ConstraintsConfigHandler(interfaces.IConstraintsConfigHandler):
    """
    Read constraints config files, applies constraints to modules.

      a list(), a [], a dict(), a set() (possibly containing RangeValue, PerfectMatch and NotNull)
      IgnoreMember
      RangeValue(low, high)
      NotNull
      PerfectMatch('bytestr')

    """
    valid_names = ['IgnoreMember', 'NotNull', 'RangeValue', 'PerfectMatch', 'ListLimitDepthValidation']
    _rv = re.compile(r'''(?P<fn>RangeValue\((?P<args>[^)]+)\))''')
    _pm = re.compile(r'''(?P<fn>PerfectMatch\('(?P<args>[^']+)'\))''')
    _nn = re.compile(r'''(?P<fn>NotNull)[,]*,?''')
    _ld = re.compile(r'''(?P<fn>ListLimitDepthValidation\((?P<args>[^)]+)\))''')

    def read(self, filename):
        """
        Read the constraints list from a file

        :param filename:
        :return:
        """
        if not os.access(filename, os.F_OK):
            raise IOError("File not found")
        # read the constraint file
        parser = ConfigParser.RawConfigParser()
        parser.optionxform = str
        parser.read(filename)
        # prepare the return object
        _constraints = ModuleConstraints()
        # each section anem is the name of the target structure
        for struct_name in parser.sections():
            log.debug('handling structure %s', struct_name)
            if struct_name not in _constraints:
                _constraints[struct_name] = RecordConstraints()
            # each config entry is a field and its IConstraint
            for field, value in parser.items(struct_name):
                log.debug('%s: field %s ::= %s', struct_name, field, value)
                try:
                    value = self._parse(value)
                except ValueError, e:
                    raise ValueError("%s: struct_name: %s Field: %s constraint: %s" % (
                                     e.message, struct_name, field, value))
                # each field can only have one IConstraint (which can be a list of)
                if field not in _constraints[struct_name]:
                    _constraints[struct_name][field] = []
                if isinstance(value, list):
                    _constraints[struct_name][field].extend(value)
                else:
                    _constraints[struct_name][field].append(value)
        return _constraints

    def _parse(self, value):
        if IgnoreMember.__name__ == value:
            return IgnoreMember
        elif IgnoreMember.__name__ in value:
            raise ValueError("IgnoreMember should be alone as a constraint")

        # TODO use re and .start(groups)
        if '[' == value[0]:
            remnant = value[1:-1]
            log.debug('list is %s', remnant)
            _args = []
            # check for functions in the list
            for fn in [self._rv, self._pm, self._nn]:
                res = []
                # find all fn
                for x in fn.finditer(remnant):
                    log.debug("Found fn %s", x.group('fn'))
                    res.append(x.group('fn'))
                # now parse each fn
                for match in res:
                    _args.append(self._parse_c(match))
                    # remove them from the parsing lefts
                    remnant = remnant.replace(match, "")
                    log.debug("remnant is %s", remnant)
            # now handle other element in list, like integers and floats
            _class_type = list
            args = remnant.split(',')
            for x in args:
                if '' == x.strip():
                    continue
                else:
                    _args.append(self._try_numbers(x))
            return _class_type(_args)
        else:
            return self._parse_c(value)

    def _parse_c(self, value):
        """
        Parse the function and args for a known function.

        :param value:
        :return:
        """
        if 'NotNull' in value:
            return NotNull
        # get the function name
        _t = value.split('(')
        _class_name = _t[0]
        args = _t[1][:-1]
        # else its a RangeValue or a PerfectMatch
        log.debug('we have a IConstraint %s', _class_name)
        if _class_name not in ['RangeValue', 'PerfectMatch', 'ListLimitDepthValidation']:
            raise ValueError('invalid constraints near %s', _class_name)
        # we know the constraint
        _class_type = getattr(sys.modules[__name__], _class_name)
        log.debug('args: %s', args)
        # look at the args
        _args = None
        if _class_name == 'RangeValue':
            _args = self._rv.search(value).group('args').split(',')
            assert len(_args) == 2
            _args = [self._try_numbers(x) for x in _args]
            return _class_type(*_args)
        elif _class_name == 'PerfectMatch':
            _args = self._pm.search(value).group('args')
            return _class_type(_args)
        elif _class_name == 'ListLimitDepthValidation':
            _args = self._ld.search(value).group('args')
            assert ',' not in _args
            _args = self._try_numbers(_args)
            return _class_type(_args)
        else:
            raise RuntimeError('no such constraint %s',_class_name)

    def _try_numbers(self, _arg):
        ret = None
        try:
            if '0x' in _arg.lower():
                # try an hex
                ret = int(_arg, 16)
            elif '.' in _arg:
                # try a float
                ret = float(_arg)
            else:
                # try an int
                ret = int(_arg)
        except ValueError, e:
            ret = str(_arg)
        return ret


class ModuleConstraints(interfaces.IModuleConstraints, dict):
    """
    Holds the constraints for all record types of a module.
    """
    def get_records(self):
        """get the list of record names."""
        return self.keys()

    def get_constraints_for_record(self, record_name):
        """get the list of IConstraint for all fields of
        """
        return self[record_name]

class RecordConstraints(interfaces.IRecordConstraints, dict):
    """
    Holds the constraints for fields of a specific record type.
    """
    def get_fields(self):
        """get the list of field names."""
        return self.keys()

    def get_constraints_for_field(self, field_name):
        """get the list of IConstraint for a field
        """
        return self[field_name]

class IgnoreMember(interfaces.IConstraint):

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member,
    the member will be ignored by the validation engine.
    """

    def __contains__(self, obj):
        return True

class ListLimitDepthValidation(interfaces.IConstraint):

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Record  member,
    the member will be ignored by the listmodel validation engine.
    """

    def __init__(self, max_depth):
        self.max_depth = max_depth

    def __contains__(self, obj):
        return True


class RangeValue(interfaces.IConstraint):

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member,
    the member has to be between 'low' and 'high' values to be
    considered as Valid.
    """

    def __init__(self, low, high):
        self.low = low
        self.high = high

    def __contains__(self, obj):
        return self.low <= obj <= self.high

    def __eq__(self, obj):
        if isinstance(obj, RangeValue):
            return self.low == obj.low and self.high == obj.high
        return self.low <= obj <= self.high


class NotNullComparable(interfaces.IConstraint):

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member,
    the member should not be null to be considered valid by the validation engine.
    """

    def __contains__(self, obj):
        return bool(obj)

    def __eq__(self, obj):
        return bool(obj)

"""
Constraint class for the Haystack model.
If this constraints is applied on a Structure member,
the member should not be null to be considered valid by the validation engine.
"""
NotNull = NotNullComparable()


class BytesComparable(interfaces.IConstraint):

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member,
    the member should have the same bytes value and length.
    """

    def __init__(self, seq):
        self.seq = seq

    def __contains__(self, obj):
        if cmp(self, obj) == 0:
            return True
        return False

    def __cmp__(self, obj):
        import ctypes
        if isinstance(obj, type(ctypes.c_void_p)):
            if ctypes.sizeof(obj) != len(self.seq):
                return -1
            bytes = ctypes.string_at(ctypes.addressof(obj), ctypes.sizeof(obj))
            if bytes == self.seq:
                return 0
            else:
                return -1
        # check if its a ctypes
        try:
            ctypes.sizeof(obj)
            return cmp(self.seq, ctypes.string_at(
                ctypes.addressof(obj), ctypes.sizeof(obj)))
        except TypeError:
            return cmp(self.seq, obj)

PerfectMatch = BytesComparable
