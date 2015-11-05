#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

from haystack.reverse import matchers
from haystack.utils import xrange

"""
A few class that can be used to search a portion of memory
 for specific pattern (null values, pointers)
"""

log = logging.getLogger('searchers')


class AFeedbackGiver(object):
    """
    Class to give feedback at every step.
    """
    def __init__(self, steps_count):
        self.count = steps_count

    def get_steps_count(self):
        return self.count

    def feedback(self, step, val):
        """ make a feedback"""
        # log.info('processing vaddr 0x%x'%(val))
        raise NotImplementedError


class NoFeedback(AFeedbackGiver):
    def __init__(self):
        super(NoFeedback, self).__init__(1)

    def feedback(self, step, val):
        """ make a feedback"""
        log.info('processing step 0x%x', val)
        return


class AbstractSearcher(object):
    """
    Search for something in memspace.
        feedback(step, val) will be called each step
        matcher.test_match will test value for each word
    """

    def __init__(self, search_mapping, matcher, feedback):
        """
            search in searchMapping for something.
        """
        self._search_mapping = search_mapping
        self._matcher = matcher
        self._feedback = feedback
        self._values = set()
        # init the steps
        self._init_steps(
            self._search_mapping.start,
            self._search_mapping.end,
            self._feedback.get_steps_count())
        self._init()

    def _init(self):
        if not isinstance(self._matcher, matchers.AbstractMatcher):
            raise TypeError("matcher should be a AbstractMatcher")

    def _init_steps(self, start, end, steps):
        """
        calculate the steps at which feedback would be given
        """
        if steps < 1:
            return []
        self.steps = [
            i for i,o in enumerate(range(
                start,
                end,
                (end - start) / steps))]  # py 3 compatible
        return

    def _check_steps(self, step):
        if len(self.steps) == 0:
            return
        if step > self.steps[0]:
            val = self.steps.pop(0)
            self._feedback.feedback(step, val)
        return

    def get_search_mapping(self):
        return self._search_mapping


class WordAlignedSearcher(AbstractSearcher):
    """
    Search for something in memspace.
        feedback(step, val) will be called each step
        matcher.test_match will test value for each word
    """

    def __init__(self, search_mapping, matcher, feedback, word_size):
        super(WordAlignedSearcher, self).__init__(search_mapping, matcher, feedback)
        self._word_size = word_size

    def __iter__(self):
        """ Iterate over the mapping to find all valid matches """
        log.debug('iterate %s mapping for matching values', self.get_search_mapping())
        mapping = self.get_search_mapping()
        for i, vaddr in enumerate(xrange(mapping.start, mapping.end, self._word_size)):
            self._check_steps(i)  # be verbose
            if self._matcher.test_match(mapping, vaddr):
                yield vaddr
        return

    def search(self):
        """
        Enumerate all values from the self.__iter__ into a array
        """
        log.debug('search %s mapping for matching values', self.get_search_mapping())
        self._values = [t for t in self]
        return self._values


class AllocatedWordAlignedSearcher(WordAlignedSearcher):
    """
    Search for something in allocated memspace.
        feedback(step, val) will be called each step
        matcher.test_match will test value for each word
    """

    def __init__(self, heap_walker, matcher, feedback, word_size):
        """

        :param heap_walker: IHeapWalker
        :param matcher: AbstractMatcher
        :param feedback: AbstractFeedback
        :param word_size: the target platform word_size
        """
        # FIXME push get_heap_mapping to IHeapWalker
        search_heap = heap_walker._heap_mapping
        super(AllocatedWordAlignedSearcher, self).__init__(search_heap, matcher, feedback, word_size)
        self._walker = heap_walker

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
            if self._matcher.test_match(mapping, vaddr):
                yield vaddr
            if size < 2*self._word_size:
                continue
            # check each offset in that allocated chunk
            for vaddr_2 in xrange(vaddr+size, vaddr+size-self._word_size, self._word_size):
                i+=1
                self._check_steps(i)
                if self._matcher.test_match(mapping, vaddr_2):
                    yield vaddr_2
        return
