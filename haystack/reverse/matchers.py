#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

class AbstractMatcher(object):
    """
    Search for pointers by checking if the word value is a valid addresses in memspace.
    """
    def __init__(self, memory_handler):
        self._memory_handler = memory_handler

    def is_valid_address_value(self, vaddr):
        return self._memory_handler.is_valid_address_value(vaddr)

    def test_match(self, mapping, vaddr):
        """
        Test function to implement by the class
        mapping: IMemoryMapping
        vaddr: long

        returns: bool
        """
        raise NotImplementedError

class AbstractMatcherWithValue(object):
    """
    Search for pointers by checking if the word value is a valid addresses in memspace.
    """
    def __init__(self, memory_handler):
        self._memory_handler = memory_handler

    def is_valid_address_value(self, vaddr):
        return self._memory_handler.is_valid_address_value(vaddr)

    def test_match(self, mapping, vaddr):
        """
        Test function to implement by the class
        mapping: IMemoryMapping
        vaddr: long

        returns: (bool, value) or (False, None) if not matched
        """
        raise NotImplementedError

class PointerSearcher(AbstractMatcher):
    """
    Search for pointers by checking if the word value is a valid addresses in memspace.
    """
    def test_match(self, mapping, vaddr):
        try:
            word = mapping.read_word(vaddr)
        except ValueError,e:
            mapping = self._memory_handler.get_mapping_for_address(vaddr)
            word = mapping.read_word(vaddr)
        if self.is_valid_address_value(word):
            return True
        return False

class NullSearcher(AbstractMatcher):
    """
    Search for Nulls words in memspace.
    """
    def test_match(self, mapping, vaddr):
        try:
            word = mapping.read_word(vaddr)
        except ValueError, e:
            # we fetch the proper mapping
            mapping = self._memory_handler.get_mapping_for_address(vaddr)
            word = mapping.read_word(vaddr)
        if word == 0:
            return True
        return False

class PointerEnumerator(AbstractMatcherWithValue):
    """
    Search for pointers by checking if the word value is a valid addresses in memspace.
    return the value of the pointer.
    """
    def test_match(self, mapping, vaddr):
        try:
            word = mapping.read_word(vaddr)
        except ValueError, e:
            # we fetch the proper mapping
            mapping = self._memory_handler.get_mapping_for_address(vaddr)
            word = mapping.read_word(vaddr)
        if self.is_valid_address_value(word):
            return True, word
        return False, None
