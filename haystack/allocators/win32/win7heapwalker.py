#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import struct
import sys

import os

from haystack import constraints
from haystack import model
from haystack import target
from haystack.abc import interfaces
from haystack.allocators.win32 import winheapwalker
from haystack.allocators.win32 import win7heap


log = logging.getLogger('win7heapwalker')


class Win7HeapWalker(winheapwalker.WinHeapWalker):

    """
    Helpers functions that return pure python lists - no ctypes in here.

    Backend allocation in BlocksIndex
    FTH allocation in Heap.LocalData[n].SegmentInfo.CachedItems
    Virtual allocation
    """

    def _create_validator(self):
        return win7heap.Win7HeapValidator(self._memory_handler, self._heap_module_constraints, self._target, self._heap_module)


class Win7HeapFinder(winheapwalker.WinHeapFinder):

    def _validator_type(self):
        return win7heap.Win7HeapValidator

    def _walker_type(self):
        return Win7HeapWalker

    def _make_dual_arch_ctypes(self):
        # dual arch
        module_name_32 = 'haystack.allocators.win32.win7_32'
        _win7_32 = target.TargetPlatform.make_target_win_32('win7')
        _model_32 = model.Model(_win7_32.get_target_ctypes())
        _win7_32_module = _model_32.import_module(module_name_32)
        # TODO make dual optional
        module_name_64 = 'haystack.allocators.win32.win7_64'
        _win7_64 = target.TargetPlatform.make_target_win_64('win7')
        _model_64 = model.Model(_win7_64.get_target_ctypes())
        _win7_64_module = _model_64.import_module(module_name_64)

        # different arch have different recors types.
        parser = constraints.ConstraintsConfigHandler()
        constraint_filename = os.path.join(os.path.dirname(sys.modules[__name__].__file__), 'win7heap32.constraints')
        _constraints_32 = parser.read(constraint_filename)
        constraint_filename = os.path.join(os.path.dirname(sys.modules[__name__].__file__), 'win7heap64.constraints')
        _constraints_64 = parser.read(constraint_filename)

        # KERNEL AS
        kas32 = (0x8000000, 0xFFFFFFFF)
        kas64 = (0xFFFF080000000000, 0xFFFFFFFFFFFFFFFF)

        _cpu = dict()
        _cpu[32] = {'model': _model_32, 'target': _win7_32, 'module': _win7_32_module,
                    'constraints': _constraints_32, 'signature_offset': 100, 'kernel_as': kas32}
        _cpu[64] = {'model': _model_64, 'target': _win7_64, 'module': _win7_64_module,
                    'constraints': _constraints_64, 'signature_offset': 160, 'kernel_as': kas64}
        return _cpu

    def _get_heap_possible_kernel_pointer_from_heap(self, target_platform, heap):
        return target_platform.get_target_ctypes_utils().get_pointee_address(heap.BaseAddress)
