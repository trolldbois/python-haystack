#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest

from haystack import constraints
from haystack import dump_loader
from haystack import basicmodel
from test.haystack import SrcTests
from test.src import ctypes6

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
        module_constraints = parser.read('test/structures/good.constraints')
        config_constraints = module_constraints.get_constraints()
        for st, stc in config_constraints.items():
            log.debug("structure: %s", st)
            for field, c in stc.items():
                log.debug("\t field: %s constraint: %s", field, c)

        self.assertIn('Struct2', config_constraints.keys())
        s2c = config_constraints['Struct2']
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

        # erroneous. It should be a list. Always.
        field0 = s2c['field0']
        self.assertTrue(isinstance(field0, list))
        self.assertEquals(field0, [-2, -3])

        field1 = s2c['field1']
        self.assertTrue(isinstance(field1, list))
        self.assertEquals(1, field1[0].low)
        self.assertEquals(16, field1[0].high)
        self.assertEquals('RangeValue', field1[0].__class__.__name__)

        field2 = s2c['field2']
        self.assertTrue(isinstance(field2, list))
        self.assertEquals('IgnoreMember', field2[0].__name__)

        field3 = s2c['field3']
        self.assertTrue(isinstance(field3, list))
        self.assertEquals(field3, [0, 1])

        field4 = s2c['field4']
        self.assertTrue(isinstance(field4, list))
        # no special character support
        self.assertEquals('qwklqwfnkl\\x20+++[po-09', field4[0].seq)
        self.assertEquals('BytesComparable', field4[0].__class__.__name__)

        field5 = s2c['field5']
        self.assertTrue(isinstance(field5, list))
        self.assertEquals('NotNullComparable', field5[0].__class__.__name__)

        field6 = s2c['field6']
        self.assertTrue(isinstance(field6, list))
        self.assertIn(-1, field6)
        self.assertIn(1, field6)
        self.assertIn(constraints.RangeValue(2, 3), field6)
        self.assertIn(constraints.RangeValue(4, 5), field6)
        self.assertIn(constraints.PerfectMatch(b'plop'), field6)

        field7 = s2c['field7']
        self.assertTrue(isinstance(field7, list))
        self.assertEquals(field7, [-1, 0, 0.0, 1.02])

        field8 = s2c['field8']
        self.assertTrue(isinstance(field8, list))
        self.assertEquals(field8, [0x0, 0x1, 0xff, 0xffeeffee, -0x20])


class TestConstraints6(SrcTests):

    def setUp(self):
        dumpname = 'test/src/test-ctypes6.64.dump'
        self.memory_handler = dump_loader.load(dumpname)
        self.my_model = self.memory_handler.get_model()
        self.ctypes_gen64 = self.my_model.import_module("test.src.ctypes6_gen64")
        # load TU values
        self._load_offsets_values(self.memory_handler.get_name())
        ##

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None

    def test_dynamic_constraints(self):

        # the constraints are imposed through code.
        dyna_validator = ctypes6.NodeDynamicValidator()
        module_constraints = constraints.ModuleConstraints()
        module_constraints.set_dynamic_constraints('struct_Node', dyna_validator)
        self.validator = basicmodel.CTypesRecordConstraintValidator(self.memory_handler, module_constraints)

        # should be valid.
        node1 = self.offsets['test2'][0]
        for instance_addr in [node1]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertTrue(self.validator.is_valid(node))

        # should be invalid.
        node2 = self.offsets['test3'][0]  # 0xdeadbabe
        items1 = self.offsets['mid_list'][0]
        items2 = self.offsets['end_list'][0]
        for instance_addr in [items1, items2, node2]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertFalse(self.validator.is_valid(node))

    def test_dynamic_sub_constraints(self):

        # the constraints are imposed through code.
        # this one only accepts head and tail struct_entry values.
        entry_validator = ctypes6.EntryDynamicValidator(self.memory_handler)
        module_constraints = constraints.ModuleConstraints()
        module_constraints.set_dynamic_constraints('struct_entry', entry_validator)
        self.validator = basicmodel.CTypesRecordConstraintValidator(self.memory_handler, module_constraints)

        # should be valid. its the head
        node1 = self.offsets['test2'][0]  # head
        node2 = self.offsets['test3'][0]  # tail
        items1 = self.offsets['start_list'][0]
        items2 = self.offsets['end_list'][0]
        for instance_addr in [node1, node2, items1, items2]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertTrue(self.validator.is_valid(node))

        # should be invalid.
        items_mid = self.offsets['mid_list'][0]
        head_first = self.offsets['head_loop_first_item'][0]
        head_last = self.offsets['head_loop_last_item'][0]
        for instance_addr in [items_mid, head_first, head_last]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertFalse(self.validator.is_valid(node))

    def test_config_constraints(self):

        # the constraints are imposed through config file.
        parser = constraints.ConstraintsConfigHandler()
        module_constraints = parser.read('test/src/ctypes6.constraints')
        self.validator = basicmodel.CTypesRecordConstraintValidator(self.memory_handler, module_constraints)

        # should be valid.
        node1 = self.offsets['test2'][0]
        node2 = self.offsets['test3'][0]  # 0xdeadbabe
        for instance_addr in [node1, node2]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertTrue(self.validator.is_valid(node))

        # should be invalid.
        items1 = self.offsets['mid_list'][0]
        items2 = self.offsets['end_list'][0]
        for instance_addr in [items1, items2]:
            m = self.memory_handler.get_mapping_for_address(instance_addr)
            node = m.read_struct(instance_addr, self.ctypes_gen64.struct_Node)
            self.assertFalse(self.validator.is_valid(node))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("constraints").setLevel(logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(logging.DEBUG)
    # logging.getLogger("listmodel").setLevel(logging.DEBUG)
    unittest.main(verbosity=2)
