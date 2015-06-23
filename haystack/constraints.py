#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This module holds some basic constraint class for the Haystack model.
"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
# never import ctypes globally
log = logging.getLogger('constraints')


class IgnoreMember:

    """
    Constraint class for the Haystack model.
    If this constraints is applied on a Structure member,
    the member will be ignored by the validation engine.
    """

    def __contains__(self, obj):
        return True


class RangeValue:

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
        return self.low <= obj <= self.high


class NotNullComparable:

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


class BytesComparable:

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
        if isinstance(obj, type(ctypes.c_void_p)):
            if ctypes.sizeof(obj) != len(seq):
                return -1
            bytes = ctypes.string_at(ctypes.addressof(obj), ctypes.sizeof(obj))
            if bytes == self.seq:
                return 0
            else:
                return -1
        return cmp(self.seq, ctypes.string_at(
            ctypes.addressof(obj), ctypes.sizeof(obj)))

PerfectMatch = BytesComparable
