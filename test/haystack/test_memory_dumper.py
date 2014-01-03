#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import os
import unittest
import logging
import shutil
import tempfile
import time
import subprocess
import sys

from haystack import model
from haystack import memory_dumper

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

class TestMemoryDumper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # run make.py
        import os, sys
        if not os.geteuid()==0:
            raise RuntimeError("Memory dump test can only be run as root. Please sudo")

    def get_folder_size(self, folder):
        folder_size = 0
        for (path, dirs, files) in os.walk(folder):
            for file in files:
                filename = os.path.join(path, file)
                folder_size += os.path.getsize(filename)
        return folder_size

    def run_app_test(self, testName, stdout=sys.stdout):
        if testName not in self.tests:
            raise ValueError("damn, please choose testName in %s"%(self.tests.keys()))
        appname = self.tests[testName]
        srcDir = os.path.sep.join([os.getcwd(), 'test', 'src'])
        tgt = os.path.sep.join([srcDir, appname])
        if not os.access(tgt, os.F_OK):
            print '\nCould not find test binaries', tgt
            print 'HAVE YOU BUILD THEM ?'
            raise IOError
        return subprocess.Popen([tgt], stdout=stdout)

class TestMemoryDumper32(TestMemoryDumper):
    """Tests MemoryDumper with 3 format types.
    
    Tests : 
    for each format, 
        launch a process
        dump the heap
        kill the process
        launch a process
        dump the heap and stack
        kill the process
        launch a process
        dump all the memory mappings
        kill the process
        compare size which should be incremental
        compare mappings files which should be the same
    """

    def setUp(self):
        from haystack import types
        types.reload_ctypes(4,4,8)
        self.tgts = []
        self.process = None
        self.tests = {  "test1": "test-ctypes1.%d"%(32),
                        "test2": "test-ctypes2.%d"%(32),
                        "test3": "test-ctypes3.%d"%(32),
                     }

    def tearDown(self):
        if self.process is not None:
            try:
                self.process.kill()
            except OSError as e:
                pass
        for f in self.tgts:
            if os.path.isfile(f):
                os.remove(f)
            elif os.path.isdir(f):
                shutil.rmtree(f)


    def _make_tgt_dir(self):
        tgt = tempfile.mkdtemp()
        self.tgts.append(tgt)
        return tgt

    def _renew_process(self):
        self.process.kill()
        self.process = self.run_app_test('test3', stdout=self.devnull.fileno())
        time.sleep(0.1)

    def test_mappings_file(self):
        '''Checks if memory_dumper make a mappings index file'''
        tgt1 = self._make_tgt_dir()
        self.devnull = file('/dev/null')
        self.process = self.run_app_test('test1', stdout=self.devnull.fileno())
        time.sleep(0.1)
        # FIXME, heaponly is breaking machine detection.
        out1 = memory_dumper.dump(self.process.pid, tgt1, "dir", True)
        self.assertIsNotNone(file( '%s/mappings'%out1))
        self.assertGreater(len(file( '%s/mappings'%out1).readlines()), 15, 'the mappings file looks too small')

    def test_dumptype_dir(self):
        '''Checks if dumping to folder works'''
        tgt1 = self._make_tgt_dir()
        tgt2 = self._make_tgt_dir()
        tgt3 = self._make_tgt_dir()

        self.devnull = file('/dev/null')
        self.process = self.run_app_test('test3', stdout=self.devnull.fileno())
        time.sleep(0.1)
        out1 = memory_dumper.dump(self.process.pid, tgt1, "dir", True)
        self.assertEquals(out1, tgt1) # same name

        self._renew_process()
        out2 = memory_dumper.dump(self.process.pid, tgt2, "dir", True)
        self.assertEquals(out2, tgt2) # same name

        self._renew_process()
        out3 = memory_dumper.dump(self.process.pid, tgt3, "dir", False)
        self.assertEquals(out3, tgt3) # same name

        size1 = self.get_folder_size(tgt1)
        size2 = self.get_folder_size(tgt2)
        size3 = self.get_folder_size(tgt3)
        
        self.assertGreater(size1, 500) # not a null archive
        #self.assertGreater(size2, size1) # more mappings
        self.assertGreater(size3, size2) # more mappings
        print size1, size2, size3
        print file(out1+'/mappings').read()
        print '-'*80
        print file(out2+'/mappings').read()
        print '-'*80
        print file(out3+'/mappings').read()
        print '-'*80
        
        # test opening by dump_loader
        from haystack import dump_loader
        from haystack import memory_mapping
        mappings1 = dump_loader.load(out1)
        self.assertIsInstance( mappings1, memory_mapping.Mappings)

        mappings2 = dump_loader.load(out2)
        mappings3 = dump_loader.load(out3)
        
        pathnames1 = [m.pathname for m in mappings1]
        pathnames2 = [m.pathname for m in mappings2]
        pathnames3 = [m.pathname for m in mappings3]
        self.assertEquals(pathnames1, pathnames2)
        self.assertEquals(pathnames3, pathnames2)
        
        return 

    def _setUp_known_pattern(self):
        self.devnull = file('/dev/null')
        self.process = self.run_app_test('test3', stdout=subprocess.PIPE)
        time.sleep(0.1)
        tgt = self._make_tgt_dir()
        self.out = memory_dumper.dump(self.process.pid, tgt, 'dir', True)
        self.process.kill()
        return self.process.communicate()
    
    def test_known_pattern_python(self):
        (stdoutdata, stderrdata) = self._setUp_known_pattern()
        # get offset from test program        
        offsets_1 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test1" in l]
        offsets_3 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test3" in l]
        import ctypes
        print 'test pattern', ctypes
        # check offsets in memory dump
        import haystack.abouchet
        for offset in offsets_1:
            instance,found = haystack.abouchet.show_dumpname('test.src.ctypes3.struct_Node', self.out, int(offset,16), rtype='python')
            self.assertTrue(found)
            self.assertEquals(instance.val1, 0xdeadbeef)
            self.assertNotEquals(instance.ptr2, 0x0)
            pass
                
        for offset in offsets_3:
            instance,found = haystack.abouchet.show_dumpname('test.src.ctypes3.struct_test3', self.out, int(offset,16), rtype='python')
            self.assertTrue(found)
            self.assertEquals(instance.val1, 0xdeadbeef)
            self.assertEquals(instance.val1b, 0xdeadbeef)
            self.assertEquals(instance.val2, 0x10101010)
            self.assertEquals(instance.val2b, 0x10101010)
            pass

    def test_known_pattern_string(self):
        (stdoutdata, stderrdata) = self._setUp_known_pattern()
        # get offset from test program        
        offsets_1 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test1" in l]
        offsets_3 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test3" in l]
        # check offsets in memory dump
        import haystack.abouchet
        for offset in offsets_3:
            ret = haystack.abouchet.show_dumpname('test.src.ctypes3.struct_test3', self.out, int(offset,16), rtype='string')
            self.assertIn( '"val1": 3735928559L', ret)
            self.assertIn( '"val2": 269488144L', ret)
            self.assertIn( '"val2b": 269488144L', ret)
            self.assertIn( '"val1b": 3735928559L', ret)
            self.assertIn( 'True', ret)
            pass

    def test_known_pattern_json(self):
        (stdoutdata, stderrdata) = self._setUp_known_pattern()
        # get offset from test program        
        offsets_1 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test1" in l]
        offsets_3 = [l.split(' ')[1] for l in stdoutdata.split('\n') if "test3" in l]
        # check offsets in memory dump
        import haystack.abouchet
        for offset in offsets_3:
            self.assertRaises(ValueError, haystack.abouchet.show_dumpname, 'test.src.ctypes3.struct_test3', self.out, int(offset,16), rtype='json' )
            pass
                



if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)


