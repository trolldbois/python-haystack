#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
from haystack.reverse import searchers
from haystack.reverse import matchers
from haystack.utils import xrange

log = logging.getLogger('enumerators')

"""
performance test:

WordAlignedEnumerator: 16028 pointers, timeit 11.74
AllocatedWordAlignedEnumerator: 596 pointers, timeit 0.20

"""

class WordAlignedEnumerator(searchers.WordAlignedSearcher):
    """
    return vaddr,value
    expect a boolean, value tuple from test_match
    """
    def _init(self):
        if not isinstance(self._matcher, matchers.AbstractMatcherWithValue):
            raise TypeError("matcher should be a AbstractMatcherWithValue")

    def __iter__(self):
        """ Iterate over the mapping to find all valid matches """
        mapping = self.get_search_mapping()
        for i, vaddr in enumerate(xrange(mapping.start, mapping.end, self._word_size)):
            self._check_steps(i)  # be verbose
            # expect a boolean, value tuple from testMatch
            b, val = self._matcher.test_match(mapping, vaddr)
            if b:
                yield (vaddr, val)
        return


class AllocatedWordAlignedEnumerator(searchers.AllocatedWordAlignedSearcher):
    """
    return vaddr,value
    expect a boolean, value tuple from test_match
    """
    def _init(self):
        if not isinstance(self._matcher, matchers.AbstractMatcherWithValue):
            raise TypeError("matcher should be a AbstractMatcherWithValue")

    def __iter__(self):
        """
        Iterate over the allocated chunk of this heap mapping to find all valid matches
        """
        log.debug('iterate allocated chunks in %s heap mapping for matching values', self.get_search_mapping())
        mapping = self.get_search_mapping()
        i = 0
        for vaddr, size in self._walker.get_user_allocations():
            self._check_steps(i)
            # check head of chunk
            # expect a boolean, value tuple from testMatch
            b, val = self._matcher.test_match(mapping, vaddr)
            if b:
                yield (vaddr, val)
            if size < 2*self._word_size:
                continue
            # check each offset in that allocated chunk
            for vaddr_2 in xrange(vaddr+size, vaddr+size-self._word_size, self._word_size):
                i+=1
                self._check_steps(i)
                # expect a boolean, value tuple from testMatch
                b, val = self._matcher.test_match(mapping, vaddr_2)
                if b:
                    yield (vaddr_2, val)
        return