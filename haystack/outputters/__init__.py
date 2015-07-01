# -*- coding: utf-8 -*-

"""
:mod:`haystack.outputs` -- classes that create an output
==============================================================================

"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class Outputter(object):

    """ Outputter interface """

    def __init__(self, mappings):
        self.mappings = mappings

    def parse(self, obj, prefix='', depth=10):
        raise NotImplementedError('Please define parse')
