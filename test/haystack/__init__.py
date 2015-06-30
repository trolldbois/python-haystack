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

    def _load_offsets_values(self, dumpname):
        """read <dumpname>.stdout to get offsets given by the binary."""
        offsets = dict()
        values = dict()
        sizes = dict()
        for line in open('%s.stdout' %
                         (dumpname[:-len('.dump')]), 'rb').readlines():
            if line.startswith('s: '):
                # start
                fields = line[3:].split(' ')
                name = fields[0].strip()
            elif line.startswith('o: '):
                # offset
                fields = line[3:].split(' ')
                k, v = fields[0], int(fields[1].strip(), 16)
                if k not in offsets:
                    offsets[k] = []
                offsets[k].append(v)
            elif line.startswith('v: '):
                # value of members
                fields = line[3:].split(' ')
                k, v = fields[0], ' '.join(fields[1:]).strip()
                n = '%s.%s' % (name, k)
                values[n] = v
            elif line.startswith('t: '):
                # sizeof
                fields = line[3:].split(' ')
                k, v = fields[0], fields[1].strip()
                sizes[name] = v
        self.values = values
        self.offsets = offsets
        self.sizes = sizes
        return

if __name__ == '__main__':
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
