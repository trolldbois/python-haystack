#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module."""

import unittest

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class SrcTests(unittest.TestCase):

    def tearDown(self):
        self.values = None
        self.offsets = None
        self.sizes = None

    @classmethod
    def _load_offsets_values(cls, dumpname):
        """read <dumpname>.stdout to get offsets given by the binary."""
        offsets = dict()
        values = dict()
        sizes = dict()
        fin = open('%s.stdout' % (dumpname[:-len('.dump')]), 'rb')
        for line in fin.readlines():
            if line.startswith(b's: '):
                # start
                fields = line[3:].split(b' ')
                name = fields[0].strip().decode()
            elif line.startswith(b'o: '):
                # offset
                fields = line[3:].split(b' ')
                k, v = fields[0].decode(), int(fields[1].strip(), 16)
                if k not in offsets:
                    offsets[k] = []
                offsets[k].append(v)
            elif line.startswith(b'v: '):
                # value of members
                fields = line[3:].split(b' ')
                k, v = fields[0].decode(), b' '.join(fields[1:]).strip()
                n = '%s.%s' % (name, k)
                values[n] = v
            elif line.startswith(b't: '):
                # sizeof
                fields = line[3:].split(b' ')
                k, v = fields[0].decode(), fields[1].strip()
                sizes[name] = v
            elif line.startswith(b'rs: '):
                # sizeof record
                fields = line[4:].split(b' ')
                name, v = fields[0].decode(), int(fields[1].strip())
                sizes[name] = v
        cls.values = values
        cls.offsets = offsets
        cls.sizes = sizes
        fin.close()
        return

if __name__ == '__main__':
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
