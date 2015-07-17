# -*- coding: utf-8 -*-

"""
:mod:`haystack.outputs` -- classes that create an output
==============================================================================

"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class Outputter(object):

    """ Outputter interface """

    def __init__(self, memory_handler):
        self._memory_handler = memory_handler
        self._ctypes = self._memory_handler.get_target_platform().get_target_ctypes()
        self._utils = self._memory_handler.get_ctypes_utils()
        self._model = self._memory_handler.get_model()

    def parse(self, obj, prefix='', depth=10):
        raise NotImplementedError('Please define parse')
