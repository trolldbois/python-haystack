#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest

from haystack import constraints
from haystack import target
import haystack.model

log = logging.getLogger("test_constraints")


class TestConstraints(unittest.TestCase):
    """
    # possible values for a constraint
#  a list(), a [], a dict(), a set()
#  IgnoreMember
#  RangeValue
#  NotNull
#  PerfectMatch
    """

    def test_read(self):
        parser = constraints.ConstraintsConfigHandler()
        _constraints = parser.read('test/structures/good.constraints')

        for st, stc in _constraints.items():
            log.debug("structure: %s", st)
            for field, c in stc.items():
                log.debug("\t field: %s constraint: %s", field, c)

        self.assertIn('Struct2', _constraints.keys())
        s2c = _constraints['Struct2']
        self.assertNotIn('fieldC', s2c.keys())
        self.assertIn('field0', s2c.keys())
        self.assertIn('field1', s2c.keys())
        self.assertIn('field2', s2c.keys())
        self.assertIn('field3', s2c.keys())
        self.assertIn('field4', s2c.keys())
        self.assertIn('field5', s2c.keys())
        self.assertIn('field6', s2c.keys())
        self.assertIn('field7', s2c.keys())
        self.assertIn('field8', s2c.keys())
        self.assertIn('FiELD9', s2c.keys())

        field0 = s2c['field0']
        self.assertEquals(field0, [-2, -3])

        field1 = s2c['field1']
        self.assertEquals(1, field1.low)
        self.assertEquals(16, field1.high)
        self.assertEquals('RangeValue', field1.__class__.__name__)

        field2 = s2c['field2']
        self.assertEquals('IgnoreMember', field2.__name__)

        field3 = s2c['field3']
        self.assertEquals(field3, [0, 1])

        field4 = s2c['field4']
        # no special character support
        self.assertEquals('qwklqwfnkl\\x20+++[po-09', field4.seq)
        self.assertEquals('BytesComparable', field4.__class__.__name__)

        field5 = s2c['field5']
        self.assertEquals('NotNullComparable', field5.__class__.__name__)

        field6 = s2c['field6']
        self.assertTrue(isinstance(field6, list))
        self.assertIn(-1, field6)
        self.assertIn(1, field6)
        self.assertIn(constraints.RangeValue(2, 3), field6)
        self.assertIn(constraints.RangeValue(4, 5), field6)
        self.assertIn(constraints.PerfectMatch('plop'), field6)

        field7 = s2c['field7']
        self.assertEquals(field7, [-1, 0, 0.0, 1.02])

        field8 = s2c['field8']
        self.assertEquals(field8, [0x0, 0x1, 0xff, 0xffeeffee, -0x20])

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)
