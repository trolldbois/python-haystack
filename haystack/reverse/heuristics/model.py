# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
from haystack.abc import interfaces

log = logging.getLogger('model')


class FieldAnalyser(object):
    """

    """
    def __init__(self, memory_handler):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError('memory_handler should be an IMemoryHandler')
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()

    def make_fields(self, structure, offset, size):
        """
        @param structure: the structure object, with a bytes()
        @param offset: the offset of the field to analyze
        @param size: the size of said field

        @return False, or [Field(), ]
        """
        raise NotImplementedError('This should be implemented.')


class StructureAnalyser(object):
    """
    StructureAnalyzer should apply heuristics on the structure, all fields included,
    and try to determine specific field types that are identifiable with a
    full structure-view.
    """

    def __init__(self, memory_handler):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError('memory_handler should be an IMemoryHandler')
        self._memory_handler = memory_handler
        self._target = self._memory_handler.get_target_platform()

    def analyze_fields(self, structure):
        """
        @param structure: the AnonymousStructure to analyze and modify

        @returns
        """
        raise NotImplementedError('This should be implemented.')
