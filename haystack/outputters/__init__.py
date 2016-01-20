# -*- coding: utf-8 -*-

"""
:mod:`haystack.outputs` -- classes that create an output
==============================================================================

"""

from haystack import utils

class Outputter(object):

    """ Outputter interface """

    def __init__(self, memory_handler):
        self._memory_handler = memory_handler
        self._ctypes = self._memory_handler.get_target_platform().get_target_ctypes()
        self._utils = utils.Utils(self._ctypes)
        self._model = self._memory_handler.get_model()
        self._addr_cache = {}

    def parse(self, obj, prefix='', depth=10):
        raise NotImplementedError('Please define parse')
