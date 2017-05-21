#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

from __future__ import print_function
import logging
import unittest

from haystack.reverse import re_string

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"


class TestReString(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # context.get_context('test/src/test-ctypes3.dump')
        cls.context = None
        cls.test1 = b'''C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00j\x00a\x00l\x00\\\x00A\x00p\x00p\x00D\x00a\x00t\x00a\x00\\\x00R\x00o\x00a\x00m\x00i\x00n\x00g\x00\\\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00\\\x00I\x00n\x00t\x00e\x00r\x00n\x00e\x00t\x00 \x00E\x00x\x00p\x00l\x00o\x00r\x00e\x00r\x00\\\x00Q\x00u\x00i\x00c\x00k\x00 \x00L\x00a\x00u\x00n\x00c\x00h\x00\\\x00d\x00e\x00s\x00k\x00t\x00o\x00p\x00.\x00i\x00n\x00i\x00\x00\x00'''
        cls.test2 = b'''\x4C\x00\x6F\x00\xEF\x00\x63\x00\x20\x00\x4A\x00\x61\x00\x71\x00\x75\x00\x65\x00\x6D\x00\x65\x00\x74\x00\x00\x00'''
        cls.test3 = b'''\\\x00R\x00E\x00G\x00I\x00S\x00T\x00R\x00Y\x00\\\x00U\x00S\x00E\x00R\x00\\\x00S\x00-\x001\x00-\x005\x00-\x002\x001\x00-\x002\x008\x008\x004\x000\x006\x003\x000\x007\x003\x00-\x003\x003\x002\x009\x001\x001\x007\x003\x002\x000\x00-\x003\x008\x001\x008\x000\x003\x009\x001\x009\x009\x00-\x001\x000\x000\x000\x00_\x00C\x00L\x00A\x00S\x00S\x00E\x00S\x00\\\x00W\x00o\x00w\x006\x004\x003\x002\x00N\x00o\x00d\x00e\x00\\\x00C\x00L\x00S\x00I\x00D\x00\\\x00{\x007\x006\x007\x006\x005\x00B\x001\x001\x00-\x003\x00F\x009\x005\x00-\x004\x00A\x00F\x002\x00-\x00A\x00C\x009\x00D\x00-\x00E\x00A\x005\x005\x00D\x008\x009\x009\x004\x00F\x001\x00A\x00}\x00'''
        cls.test4 = b'''edrtfguyiopserdtyuhijo45567890oguiy4e65rtiu\x07\x08\x09\x00'''
        cls.test5 = b'''edrt\x00fguyiopserdtyuhijo45567890oguiy4e65rtiu\xf1\x07\x08\x09\x00\x00'''
        cls.test6 = b'''\xf3drtfguyiopserdtyuhijo45567890oguiy4e65rtiu\xf1\x07\x08\x09\x00'''
        cls.test7 = b'\x1e\x1c\x8c\xd8\xcc\x01\x00'  # pure crap
        cls.test8 = b'C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00D\x00r\x00i\x00v\x00e\x00r\x00S\x00t\x00o\x00r\x00e\x00\x00\x00\xf1/\xa6\x08\x00\x00\x00\x88,\x00\x00\x00C\x00:\x00\\\x00P\x00r\x00o\x00g\x00r\x00a\x00m\x00 \x00F\x00i\x00l\x00e\x00s\x00 \x00(\x00x\x008\x006\x00)\x00\x00\x00P\x00u\x00T\x00Y\x00'
        cls.test9 = b'\x01\x01@\x00C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00'
        cls.test10 = b'''\x4C\x6F\xEF\x63\x20\x4A\x61\x71\x75\x65\x6D\x65\x74'''
        cls.test11 = b'D\x00c\x00o\x00m\x00L\x00a\x00u\x00n\x00c\x00h\x00\x00\x00T\x00e\x00r\x00m\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00\x00\x00'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_startsWithNulTerminatedString(self):
        # self.skipTest('')

        size, codec, txt = re_string.startsWithNulTerminatedString(self.test1)
        self.assertEqual(size, len(self.test1))

        pass

    @unittest.expectedFailure
    def test_try_decode_string(self):
        # self.skipTest('')

        size, codec, txt = re_string.try_decode_string(self.test1)
        self.assertEqual(size, len(self.test1))

        size, codec, txt = re_string.try_decode_string(self.test2)
        self.assertEqual(size, len(self.test2))

        size, codec, txt = re_string.try_decode_string(self.test3)
        self.assertEqual(size, len(self.test3))

        size, codec, txt = re_string.try_decode_string(self.test4)
        self.assertEqual(size, len(self.test4) - 4)

        size, codec, txt = re_string.try_decode_string(self.test5)
        self.assertEqual(size, len(self.test5) - 5)

        ret = re_string.try_decode_string(self.test7)
        self.assertFalse(ret)

        size, codec, txt = re_string.try_decode_string(self.test8)
        self.assertEqual(size, len(self.test8))

        pass

    def test_testEncoding(self):
        # self.skipTest('')

        uni = self.test1
        size, encoded = re_string.testEncoding(uni, 'utf-16le')
        self.assertEqual(size, len(uni))

        x3 = self.test2
        size, encoded = re_string.testEncoding(x3, 'utf-16le')
        self.assertEqual(size, len(x3))

        size, encoded = re_string.testEncoding(self.test4, 'utf-16le')
        self.assertEqual(size, -1)

        size, encoded = re_string.testEncoding(self.test4, 'utf-8')
        self.assertEqual(size, len(self.test4))

        pass

    def test_testAllEncodings(self):

        # self.skipTest('')

        uni = self.test1
        solutions = re_string.testAllEncodings(uni)
        size, codec, encoded = solutions[0]
        self.assertEqual(size, len(uni), '%s' % codec)

        x3 = self.test2
        solutions = re_string.testAllEncodings(x3)
        size, codec, encoded = solutions[0]
        self.assertEqual(size, len(x3))

        solutions = re_string.testAllEncodings(self.test3)
        size, codec, encoded = solutions[0]
        self.assertEqual(size, len(self.test3))

        solutions = re_string.testAllEncodings(self.test4)
        size, codec, encoded = solutions[0]
        self.assertEqual(size, len(self.test4))

        pass

    def test_nocopy_class(self):
        # self.skipTest('')
        s = '1234567890'
        x = re_string.Nocopy(s, 2, 9)
        x1 = s[2:9]
        self.assertEqual(len(x), len(x1))
        for i in range(len(x)):
            self.assertEqual(x[i], x1[i])
        #
        val = x[2:4]
        self.assertEqual(val, '56')
        self.assertEqual(val, x[2:4])
        self.assertEqual(s[4:-1], x[2:])
        self.assertEqual(s[2:-1], x[:16])
        self.assertEqual(s[2:-1], x[:])
        self.assertEqual(s[2:-1], x[0:])
        self.assertEqual(s[2:-1], x)

        self.assertEqual(re_string.Nocopy(s, 9, 10), s[9:10])
        self.assertEqual(re_string.Nocopy(s, 9, 10), '0')
        self.assertEqual(re_string.Nocopy(s, -2, -1), '9')

        # self.assertRaises(re_string.Nocopy(s,9,11))

    def test_rfind_utf16(self):
        # print len(self.test1)
        self.assertEqual(0, re_string.rfind_utf16(self.test1, 0, len(self.test1), True, 4))
        self.assertEqual(0, re_string.rfind_utf16(self.test2, 0, len(self.test2), True, 4))
        self.assertEqual(0, re_string.rfind_utf16(self.test3, 0, len(self.test3), True, 4))
        self.assertEqual(-1, re_string.rfind_utf16(self.test4, 0, len(self.test4), True, 4))
        self.assertEqual(-1, re_string.rfind_utf16(self.test5, 0, len(self.test5), True, 4))
        self.assertEqual(-1, re_string.rfind_utf16(self.test6, 0, len(self.test6), True, 4))
        self.assertEqual(-1, re_string.rfind_utf16(self.test7, 0, len(self.test7), True, 4))
        # truncated last field
        # print repr(self.test8[120:])
        self.assertEqual(122, re_string.rfind_utf16(self.test8, 0, len(self.test8), False, 4))
        # find start with limited size
        self.assertEqual(0, re_string.rfind_utf16(self.test8, 0, 64, True, 4))
        # middle field ( 12+64 )
        self.assertEqual(12, re_string.rfind_utf16(self.test8, 64, 58, True, 4))
        # non aligned middle field ?
        # TODO self.assertEqual( 4, re_string.rfind_utf16(self.test9, 0,
        # len(self.test9) ))
        ##
        # self.assertEqual(0, re_string.rfind_utf16(self.test11, 0, 48, False, 4))
        print(re_string.rfind_utf16(self.test11, 0, 44, False, 4))

    def test_find_ascii(self):
        self.assertEqual(
            (-1, -1), re_string.find_ascii(self.test1, 0, len(self.test1)))
        self.assertEqual(
            (0, 43), re_string.find_ascii(
                self.test4, 0, len(
                    self.test4)))
        self.assertEqual(
            (0, 4), re_string.find_ascii(
                self.test5, 0, len(
                    self.test5)))
        self.assertEqual(
            (0, 39), re_string.find_ascii(
                self.test5, 5, len(
                    self.test5) - 5))
        self.assertEqual(
            (-1, -1), re_string.find_ascii(self.test6, 0, len(self.test6)))
        self.assertEqual(
            (0, 42), re_string.find_ascii(
                self.test6, 1, len(
                    self.test6) - 1))
        self.assertEqual(
            (-1, -1), re_string.find_ascii(self.test10, 0, len(self.test10)))  # too small
        self.assertEqual(
            (0, 10), re_string.find_ascii(
                self.test10, 3, len(
                    self.test10) - 3))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
