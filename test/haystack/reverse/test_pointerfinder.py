#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import struct
import operator
import os
import unittest

from haystack import model
from haystack.mappings.base import MemoryMapping
from haystack.mappings.file import LocalMemoryMapping
from haystack.reverse import pointerfinder

from haystack import config


class TestPointer(unittest.TestCase):
    def setUp(self):
        self.config = config.make_config_linux32()
        self.config.MMAP_START = 0x0c00000
        self.config.MMAP_STOP = 0x0c01000
        self.config.MMAP_LENGTH = 4096
        self.config.STRUCT_OFFSET = 44
        self.seq = [4,4,8,128,4,8,4,4,12]
        self.mmap, self.values = self.makeMMap(self.seq)
        self.name = 'test_dump_1'
 
    def accumulate(self, iterable, func=operator.add):
        it = iter(iterable)
        total = next(it)
        yield total
        for element in it:
            total = func(total, element)
            yield total

    def makeMMap(self, seq):
        """Creates a home made mapping with pointer values in the middle of 
        garbage"""
        start = self.config.MMAP_START
        offset = self.config.STRUCT_OFFSET
        nsig = [offset]
        nsig.extend(seq)
        indices = [ i for i in self.accumulate(nsig)]
        dump = [] #b''
        values = []
        for i in range(0,self.config.MMAP_LENGTH, self.config.get_word_size()): 
            if i in indices:
                dump.append( struct.pack('I',start+i) )
                values.append(start+i)
            else:
                dump.append( struct.pack('I',0x2e2e2e2e) )
        
        if len(dump) != self.config.MMAP_LENGTH/self.config.get_word_size() :
            raise ValueError('error on length dump %d expected %d'%( len(dump), (self.config.MMAP_LENGTH/self.config.get_word_size()) ) )    
        dump2 = ''.join(dump)
        #print repr(dump2[:16]), self.config.get_word_size(), self.config.MMAP_LENGTH
        if len(dump)*self.config.get_word_size() != len(dump2):
            raise ValueError('error on length dump %d dump2 %d'%( len(dump),len(dump2)) )
        stop = start + len(dump2)
        mmap = MemoryMapping(start, stop, '-rwx', 0, 0, 0, 0, 'test_mmap')
        mmap2= LocalMemoryMapping.fromBytebuffer( mmap, dump2)
        mmap2.init_config(self.config)
        return mmap2, values




class TestPointerSearcher(TestPointer):

    def test_iter(self):
        self.pointerSearcher = pointerfinder.PointerSearcher(self.mmap)
        iters = [value for value in self.pointerSearcher ]
        values = self.pointerSearcher.search()
        self.assertEqual( iters, values)
        self.assertEqual( self.values, values)
        self.assertEqual( self.values, iters)


class TestPointerEnumerator(TestPointer):

    def test_iter(self):
        self.pointerEnum = pointerfinder.PointerEnumerator(self.mmap)
        values = [value for offset,value in self.pointerEnum ]
        offsets = [offset for offset,value in self.pointerEnum ]
        values_2 = [value for offset,value in self.pointerEnum.search() ]
        offsets_2 = [offset for offset,value in self.pointerEnum.search() ]

        self.assertEqual( values, values_2)
        self.assertEqual( offsets, offsets_2)
        self.assertEqual( self.values, values)
        self.assertEqual( self.values, values_2)

        nsig = [self.config.MMAP_START+self.config.STRUCT_OFFSET]
        nsig.extend(self.seq)
        indices = [ i for i in self.accumulate(nsig)]
        self.assertEqual( indices, offsets)
        self.assertEqual( indices, offsets_2)



if __name__ == '__main__':
        unittest.main()

