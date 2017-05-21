#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

from __future__ import print_function
import unittest
import logging

from haystack import target
from haystack import dump_loader
from haystack.abc import interfaces

from haystack.reverse import fieldtypes
from haystack.reverse import context
from haystack.reverse import structure
from haystack.reverse.heuristics import dsa

from test.testfiles import putty_7124_win7
from test.testfiles import zeus_856_svchost_exe

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"


log = logging.getLogger('test_field_analyser')


class FS:
    def __init__(self, bytes, vaddr=0):
        self._bytes = bytes
        self._vaddr = vaddr

    def __len__(self):
        return len(self._bytes)

    def reset(self):
        self._fields = []
        self._resolved = False
        self._resolvedPointers = False
        self._dirty = True
        self._ctype = None
        return

    @property
    def bytes(self):
        return self._bytes


class FakeMemoryHandler(interfaces.IMemoryHandler):
    """Fake memoryhandler for the tests."""

    def __init__(self, target):
        self.target = target

    def get_name(self):
        return "test"

    def get_target_platform(self):
        return self.target

    def reset_mappings(self):
        return


class TestFieldAnalyser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test1 = FS(
            b'''\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00....''')
        cls.test2 = FS(
            b'''....\x00\x00\x00\x00....\x00\x00\x00\x00\x00\x00\x00\x00....\x00...\x00\x00\x00.\x00\x00\x00\x00''')
        cls.test3 = FS('''....1234aaaa.....''')
        cls.test4 = FS(
            b'''\x00\x00\x00\x00h\x00i\x00 \x00m\x00y\x00 \x00n\x00a\x00m\x00e\x00\x00\x00\xef\x00\x00\x00\x00\x00....''')
        cls.test5 = FS(
            b'\xd8\xf2d\x00P\xf3d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00CryptDllVerifyEncodedSignature\x00\x00')
        cls.test6 = FS(
            b'''edrtfguyiopserdtyuhijo45567890oguiy4e65rtiu\xf1\x07\x08\x09\x00''')
        #
        cls.test8 = FS(
            b'C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00D\x00r\x00i\x00v\x00e\x00r\x00S\x00t\x00o\x00r\x00e\x00\x00\x00\xf1/\xa6\x08\x00\x00\x00\x88,\x00\x00\x00C\x00:\x00\\\x00P\x00r\x00o\x00g\x00r\x00a\x00m\x00 \x00F\x00i\x00l\x00e\x00s\x00 \x00(\x00x\x008\x006\x00)\x00\x00\x00P\x00u\x00T\x00Y\x00')

        # new test from real case zeus.856 @0xb2e38
        real = b'\xc81\x0b\x00\xa8*\x0b\x00\x01\x00\x00\x00\x00\x00\x00\x00f \x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\xe0\xa9`\x9dz3\xd0\x11\xbd\x88\x00\x00\xc0\x82\xe6\x9a\xed\x03\x00\x00\x01\x00\x00\x00\xc8\xfc\xbe\x02p\x0c\x00\x00\x08\x00\x00\x00\x1d\x00\x02\x00L\xfd\xbe\x02\xd8\x91\x1b\x01\x00\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00R\x00S\x00V\x00P\x00 \x00T\x00C\x00P\x00 \x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00\x00\x00f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xe9\x90|\xf2\x94\x80|\x00P\xfd\x7f\x00\x00\x1c\x00\x08\x00\x00\x00\x00\x00\x00\x00t\xfc\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x00\x00\xc3\x00\x00\x00\x00\x00\x88\xb0\xd2\x01\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|h^\xd0\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\xc3\x00\x01\x00\x00\x000\x02\x1c\x00\x02\x00\x00\x00\x90\xb0\xd2\x01\x03\x00\x00\x00\x02\x00\x00\x00h^\xd0\x010\x02\x1c\x00\xd8>\xd4\x010\xf0\xfc\x00\xb8\x02\x1c\x00\xe8?\xd4\x01\xd8\x01\x1c\x00\x00\x00\x00\x00\x10\x00\x00\x00\xe8?\xd4\x01\x0c\x00\x00\x00\x05\x00\x00\x00\xf0\x06\x91|\xe0\x01\x1c\x00\x18\x00\x00\x00\xe0>\xd4\x01\x00\x00\x1c\x00\x01\x00\x00\x00\x08\x00\x00\x00\xe0\x01\x1c\x00@\x00\x00\x00\xf0?\xd4\x01\xa8\x04\x1c\x00\x00\x00\x1c\x00Om\x01\x01\x84^\xd0\x01`\x00\x00\x00\xb8\x02\x1c\x00\x00\x00\x00\x00\xd8>\xd4\x01\x88\xfc\xbe\x02F\x0f\x91|\r\x00\x00\x00\xd8>\xd4\x01\x00\x00\x1c\x00\x10<\xd4\x01\x00\x00\x00\x00\\\xfd\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02\x00\x00\xc3\x00\x0c\x00\x00\x00\x10<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00\x00\x00\x00\x00\x18<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00(\xfd\xbe\x02\xa8\x04\x1c\x00\xd0\x0c\x00\x00@\x00\x00\x00\x03\x00\x00\x00\x18<\xd4\x01\xa8\x04\x1c\x00`\xab\xf0\x00\xc8\x02\x00\x00\xec<\xca\x02\x0c\x00\x0e\x00<V_u\x00\x00\x00\x00\xf8\xfc\xbe\x02\xec<\xca\x02\x00\x00\x00\x00`\xab\xf0\x00P\xfd\xbe\x02l\xfb\x90|q\xfb\x90|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02,\xfd\xbe\x02%SystemRoot%\\system32\\rsvpsp.dll\x00\x003\x00B\x006\x004\x00B\x007\x00}\x00\x00\x00\xbe\x02\x05\x00\x00\x00\xe6-\xfd\x7f\x96\x15\x91|\xeb\x06\x91|\xa4\xfd\xbe\x02 8\xd4\x01\x10\x00\x00\x00\t\x04\x00\x00\x00\x01\x00\x00\xdc\xfa\xbe\x02\x00\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x04\x00\x00\x00\xaf\x9f\xd4w\xdc\xfa\xbe\x02\x05\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x96\x15\x91|\xeb\x06\x91|\x00\x00\x00\x00\x00\x00\x00\x00X\x00\x00\x00\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x01\x00\x00\x00\xff\xff\xff\xff\xd8\xa2\x92w\x08\xa3\x92w\xdc\xfa\xbe\x02\xd8\xfa\xbe\x02\x02\x00\x00\x80\x9c\xfa\xbe\x02\x90\x01\x1c\x00\xb0\x01\x00\x00\xe4\xfa\xbe\x02\xff\xff\xff\xff\xe0\xfc\xbe\x02\xab\xa5\x92wh^\xd0\x01\xdc\xfa\xbe\x02\x88\x01\x1c\x00\x00\x00\xc3\x00\x01\x00\x00\x00\x96\x15\x91|\x00\x00\x00\x00'
        cls.test9 = FS(real)
        cls.test9b = FS(real[636:736])

        cls.target = target.TargetPlatform.make_target_linux_32()
        cls.memory_handler = FakeMemoryHandler(cls.target)
        cls.zeroes = dsa.ZeroFields(cls.memory_handler)
        cls.utf16 = dsa.UTF16Fields(cls.memory_handler)
        cls.ascii = dsa.PrintableAsciiFields(cls.memory_handler)
        cls.ints = dsa.IntegerFields(cls.memory_handler)
        pass

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        cls.target = None

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_zeroes(self):
        fields = self.zeroes.make_fields(self.test1, 0, len(self.test1))
        self.assertEqual(len([_ for _ in fields]), 3)
        self.assertEqual(fields[0].offset, 0)
        self.assertEqual(fields[0].size, 4)
        self.assertEqual(fields[1].offset, 8)
        self.assertEqual(fields[1].size, 8)
        self.assertEqual(fields[2].offset, 28)
        self.assertEqual(fields[2].size, 4)

        fields = self.zeroes.make_fields(self.test2, 0, len(self.test2))
        self.assertEqual(len([_ for _ in fields]), 3)
        self.assertEqual(fields[0].offset, 4)
        self.assertEqual(fields[0].size, 4)
        self.assertEqual(fields[1].offset, 12)
        self.assertEqual(fields[1].size, 8)
        self.assertEqual(fields[2].offset, 32)
        self.assertEqual(fields[2].size, 4)

        fields = self.zeroes.make_fields(self.test3, 0, len(self.test3))
        self.assertEqual(len([_ for _ in fields]), 0)

        fields = self.zeroes.make_fields(self.test4, 0, len(self.test4))
        self.assertEqual(len([_ for _ in fields]), 2)

        with self.assertRaises(AssertionError):  # unaligned offset
            fields = self.zeroes.make_fields(self.test4, 1, len(self.test4))

        fields = self.zeroes.make_fields(self.test4, 4, len(self.test4))
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.zeroes.make_fields(self.test5, 0, len(self.test5))
        self.assertEqual(len([_ for _ in fields]), 1)

    def test_utf16(self):
        fields = self.utf16.make_fields(self.test1, 0, len(self.test1))
        self.assertEqual(len([_ for _ in fields]), 0)  # no utf16

        fields = self.utf16.make_fields(self.test8, 0, len(self.test8))
        self.assertEqual(len([_ for _ in fields]), 3)  # 3 utf-16

        fields = self.utf16.make_fields(self.test6, 0, len(self.test6))
        self.assertEqual(len([_ for _ in fields]), 0)

    def test_complex_utf(self):
        fields = self.utf16.make_fields(self.test9, 0, len(self.test9))
        self.assertEqual(len([_ for _ in fields]), 2)

    def test_small_int(self):
        ''' we default to word_size == 4 '''
        smallints = [b'\xff\xff\xff\xff', b'\x02\xff\xff\xff', ]
        for bytes in smallints:
            fields = self.ints.make_fields(FS(bytes), 0, 4)
            self.assertEqual(len([_ for _ in fields]), 1)
            self.assertEqual(fields[0].endianess, '<')

        smallints = [b'\xff\xff\xff\x03', b'\x00\x00\x00\x42',
                     b'\x00\x00\x00\x01', b'\x00\x00\x01\xaa', ]
        for bytes in smallints:
            fields = self.ints.make_fields(FS(bytes), 0, 4)
            self.assertEqual(len([_ for _ in fields]), 1, repr(bytes))
            self.assertEqual(fields[0].endianess, '>')

        not_smallints = [b'\xfa\xff\xfb\xff', b'\x01\xff\xff\x03', b'\x02\xff\x42\xff',
                         b'\x01\x00\x00\x01', b'\x00\x12\x01\xaa', b'\x00\xad\x00\x42',
                         b'\x00\x41\x00\x41', b'\x41\x00\x41\x00']
        for bytes in not_smallints:
            fields = self.ints.make_fields(FS(bytes), 0, 4)
            self.assertEqual(len([_ for _ in fields]), 0)

    def test_ascii(self):
        fields = self.ascii.make_fields(self.test1, 0, len(self.test1))
        self.assertEqual(len([_ for _ in fields]), 3)

        fields = self.ascii.make_fields(self.test1, 8, len(self.test1) - 8)
        self.assertEqual(len([_ for _ in fields]), 2)

        fields = self.ascii.make_fields(self.test2, 0, len(self.test2))
        self.assertEqual(len([_ for _ in fields]), 3)

        fields = self.ascii.make_fields(self.test3, 0, len(self.test3))
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.ascii.make_fields(self.test4, 0, len(self.test4))
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.ascii.make_fields(self.test3, 4, 12)
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.ascii.make_fields(self.test5, 0, len(self.test5))
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.ascii.make_fields(self.test6, 0, len(self.test6))
        self.assertEqual(len([_ for _ in fields]), 1)

        fields = self.ascii.make_fields(self.test8, 0, len(self.test8))
        self.assertEqual(len([_ for _ in fields]), 0)


class TestDSA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # context.get_context('test/src/test-ctypes3.dump')
        cls.context = None
        cls.memory_handler = dump_loader.load(putty_7124_win7.dumpname)
        cls.putty7124 = context.get_context_for_address(cls.memory_handler, putty_7124_win7.known_heaps[0][0])
        cls.dsa = dsa.FieldReverser(cls.putty7124.memory_handler)
        cls.memory_handler = cls.putty7124.memory_handler

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @unittest.expectedFailure  # 'utf16 should start on aligned byte'
    def test_utf_16_le_null_terminated(self):

        # struct_682638 in putty.7124.dump
        vaddr = 0x682638
        size = 184
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertEqual(len([_ for _ in fields]), 5)  # TODO should be 6 fields lllttp
        self.assertEqual(fields[2].field_type, fieldtypes.STRING16)
        self.assertTrue(fields[2].is_string())
        # TODO fields[3] should start at offset 12, not 10.
        self.assertEqual(fields[3].field_type, fieldtypes.STRING16)
        self.assertTrue(fields[3].is_string())
        #  print f

    def test_utf_16_le_non_null_terminated(self):
        """ non-null terminated """
        # struct_691ed8 in putty.7124.dump
        vaddr = 0x691ed8
        size = 256
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertEqual(len([_ for _ in fields]), 2)
        self.assertEqual(fields[1].field_type, fieldtypes.STRING16)
        self.assertTrue(fields[1].is_string())

    def test_ascii_null_terminated_2(self):
        """ null terminated """
        # struct_64f328 in putty.7124.dump
        vaddr = 0x64f328
        size = 72
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertEqual(len([_ for _ in fields]), 5)
        self.assertEqual(fields[3].field_type, fieldtypes.STRINGNULL)
        self.assertTrue(fields[3].is_string())

    def test_utf_16_le_null_terminated_3(self):
        ''' null terminated '''
        # in putty.7124.dump
        vaddr = 0x657488
        size = 88
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertEqual(len([_ for _ in fields]), 2)  # should be 3 Lt0?
        self.assertEqual(fields[0].field_type, fieldtypes.STRING16)
        self.assertTrue(fields[0].is_string())

    def test_big_block(self):
        ''' null terminated '''
        # in putty.7124.dump
        vaddr = 0x63d4c8  # + 1968
        size = 4088  # 128
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertLess(len([_ for _ in fields]), 879)
        #self.assertEqual( fields[35].field_type.name, fieldtypes.STRINGNULL)
        #self.assertTrue( fields[35].isString())
        strfields = [f for f in st.get_fields() if f.is_string()]
        # for f in strfields:
        #  print f.toString(),
        self.assertGreater(len(strfields), 30)

    def test_uuid(self):
        ''' null terminated '''
        # in putty.7124.dump
        vaddr = 0x63aa68
        size = 120
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertEqual(len([_ for _ in fields]), 3)
        self.assertEqual(fields[1].field_type, fieldtypes.STRING16)
        self.assertTrue(fields[1].is_string())

        pass

    def test_big_block_2(self):
        # in putty.7124.dump
        # its garbage anyway
        vaddr = 0x675b30
        size = 8184
        st = structure.AnonymousRecord(self.memory_handler, vaddr, size)
        self.dsa.reverse_record(self.context, st)
        # print repr(st.bytes)
        log.debug(st.to_string())
        fields = st.get_fields()
        self.assertLess(len([_ for _ in fields]), 890)
        #self.assertEqual( fields[35].field_type.name, fieldtypes.STRINGNULL)
        #self.assertTrue( fields[35].isString())
        fields = [f for f in st.get_fields() if f.is_string()]
        # for f in fields:
        #  print f.toString(),


class TestFieldAnalyserReal(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from haystack import dump_loader
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        cls.context = context.get_context_for_address(cls.memory_handler, 0x90000)
        cls.target = cls.memory_handler.get_target_platform()
        cls.zeroes = dsa.ZeroFields(cls.memory_handler)
        cls.utf16 = dsa.UTF16Fields(cls.memory_handler)
        cls.ascii = dsa.PrintableAsciiFields(cls.memory_handler)
        cls.ints = dsa.IntegerFields(cls.memory_handler)

        # new test from real case zeus.856 @0xb2e38
        cls.real = b'\xc81\x0b\x00\xa8*\x0b\x00\x01\x00\x00\x00\x00\x00\x00\x00f \x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\xe0\xa9`\x9dz3\xd0\x11\xbd\x88\x00\x00\xc0\x82\xe6\x9a\xed\x03\x00\x00\x01\x00\x00\x00\xc8\xfc\xbe\x02p\x0c\x00\x00\x08\x00\x00\x00\x1d\x00\x02\x00L\xfd\xbe\x02\xd8\x91\x1b\x01\x00\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00R\x00S\x00V\x00P\x00 \x00T\x00C\x00P\x00 \x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00\x00\x00f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xe9\x90|\xf2\x94\x80|\x00P\xfd\x7f\x00\x00\x1c\x00\x08\x00\x00\x00\x00\x00\x00\x00t\xfc\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x00\x00\xc3\x00\x00\x00\x00\x00\x88\xb0\xd2\x01\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|h^\xd0\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\xc3\x00\x01\x00\x00\x000\x02\x1c\x00\x02\x00\x00\x00\x90\xb0\xd2\x01\x03\x00\x00\x00\x02\x00\x00\x00h^\xd0\x010\x02\x1c\x00\xd8>\xd4\x010\xf0\xfc\x00\xb8\x02\x1c\x00\xe8?\xd4\x01\xd8\x01\x1c\x00\x00\x00\x00\x00\x10\x00\x00\x00\xe8?\xd4\x01\x0c\x00\x00\x00\x05\x00\x00\x00\xf0\x06\x91|\xe0\x01\x1c\x00\x18\x00\x00\x00\xe0>\xd4\x01\x00\x00\x1c\x00\x01\x00\x00\x00\x08\x00\x00\x00\xe0\x01\x1c\x00@\x00\x00\x00\xf0?\xd4\x01\xa8\x04\x1c\x00\x00\x00\x1c\x00Om\x01\x01\x84^\xd0\x01`\x00\x00\x00\xb8\x02\x1c\x00\x00\x00\x00\x00\xd8>\xd4\x01\x88\xfc\xbe\x02F\x0f\x91|\r\x00\x00\x00\xd8>\xd4\x01\x00\x00\x1c\x00\x10<\xd4\x01\x00\x00\x00\x00\\\xfd\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02\x00\x00\xc3\x00\x0c\x00\x00\x00\x10<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00\x00\x00\x00\x00\x18<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00(\xfd\xbe\x02\xa8\x04\x1c\x00\xd0\x0c\x00\x00@\x00\x00\x00\x03\x00\x00\x00\x18<\xd4\x01\xa8\x04\x1c\x00`\xab\xf0\x00\xc8\x02\x00\x00\xec<\xca\x02\x0c\x00\x0e\x00<V_u\x00\x00\x00\x00\xf8\xfc\xbe\x02\xec<\xca\x02\x00\x00\x00\x00`\xab\xf0\x00P\xfd\xbe\x02l\xfb\x90|q\xfb\x90|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02,\xfd\xbe\x02%SystemRoot%\\system32\\rsvpsp.dll\x00\x003\x00B\x006\x004\x00B\x007\x00}\x00\x00\x00\xbe\x02\x05\x00\x00\x00\xe6-\xfd\x7f\x96\x15\x91|\xeb\x06\x91|\xa4\xfd\xbe\x02 8\xd4\x01\x10\x00\x00\x00\t\x04\x00\x00\x00\x01\x00\x00\xdc\xfa\xbe\x02\x00\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x04\x00\x00\x00\xaf\x9f\xd4w\xdc\xfa\xbe\x02\x05\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x96\x15\x91|\xeb\x06\x91|\x00\x00\x00\x00\x00\x00\x00\x00X\x00\x00\x00\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x01\x00\x00\x00\xff\xff\xff\xff\xd8\xa2\x92w\x08\xa3\x92w\xdc\xfa\xbe\x02\xd8\xfa\xbe\x02\x02\x00\x00\x80\x9c\xfa\xbe\x02\x90\x01\x1c\x00\xb0\x01\x00\x00\xe4\xfa\xbe\x02\xff\xff\xff\xff\xe0\xfc\xbe\x02\xab\xa5\x92wh^\xd0\x01\xdc\xfa\xbe\x02\x88\x01\x1c\x00\x00\x00\xc3\x00\x01\x00\x00\x00\x96\x15\x91|\x00\x00\x00\x00'
        cls.test1 = structure.AnonymousRecord(cls.memory_handler, 0xb2e38, 904, prefix=None)
        cls.test2 = structure.AnonymousRecord(cls.memory_handler, 0xb2e38 + 636, 100, prefix=None)

        pass

    def test_utf16_1(self):
        # the issue is that if starts a utf16 fields in the middle of a word.
        # and that the gap before is not separated in a gap field
        self.assertEqual(self.real, self.test1.bytes)

        _dsa = dsa.FieldReverser(self.memory_handler)
        _dsa.reverse_record(self.context, self.test1)
        fields = self.test1.get_fields()
        fields.sort()

        nextoffset = 0
        # test is sorted
        for i, f in enumerate(self.test1.get_fields()):
            self.assertGreaterEqual(f.offset, nextoffset)
            nextoffset = f.offset + len(f)


class TestTextFieldCorrection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from haystack import dump_loader
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        cls.heap_context = context.get_context_for_address(cls.memory_handler, 0x90000)
        cls.target = cls.memory_handler.get_target_platform()

    def test_utf16_1(self):
        # struct_a4188 SIG:z4T108
        # class struct_a4028(ctypes.Structure):  # rlevel:50 SIG:T84z4 size:88
        # struct_943f8 SIG:T20i4T20z4
        # _record = self.heap_context.get_record_for_address(0xb2e38)
        _record = self.heap_context.get_record_for_address(0x943f8)
        _record.reset()
        _dsa = dsa.FieldReverser(self.memory_handler)
        _dsa.reverse_record(self.heap_context, _record)
        b = b'D\x00c\x00o\x00m\x00L\x00a\x00u\x00n\x00c\x00h\x00\x00\x00T\x00e\x00r\x00m\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00\x00\x00'
        rev = dsa.TextFieldCorrection(self.memory_handler)
        rev.reverse_record(self.heap_context, _record)
        fields = _record.get_fields()
        self.assertEqual(len(fields), 3)
        self.assertTrue(fields[0].is_string())
        self.assertTrue(fields[1].is_string())
        self.assertTrue(fields[2].is_zeroes())

        print(_record.to_string())

    def test_utf16_2(self):
        _record = self.heap_context.get_record_for_address(0xa4028)
        _record.reset()
        _dsa = dsa.FieldReverser(self.memory_handler)
        _dsa.reverse_record(self.heap_context, _record)
        rev = dsa.TextFieldCorrection(self.memory_handler)
        rev.reverse_record(self.heap_context, _record)
        fields = _record.get_fields()

        print(_record.to_string())




if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('test_field_analyser').setLevel(level=logging.DEBUG)
    # logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
    # logging.getLogger("structure").setLevel(level=logging.DEBUG)
    # logging.getLogger("field").setLevel(level=logging.DEBUG)
    logging.getLogger("dsa").setLevel(level=logging.DEBUG)
    # logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
