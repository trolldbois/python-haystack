#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import os
import unittest
import shutil
import tempfile
import time

from haystack import memory_dumper
from test.run_src_app import *

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

def get_folder_size(folder):
  folder_size = 0
  for (path, dirs, files) in os.walk(folder):
    for file in files:
      filename = os.path.join(path, file)
      folder_size += os.path.getsize(filename)
  return folder_size

class TestMemoryDumper(unittest.TestCase):
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
    self.devnull = file('/dev/null')
    self.process = run_app_test('test1', stdout=self.devnull.fileno())
    time.sleep(0.1)
    self.tgts = []

  def _renew_process(self):
    self.process.kill()
    self.process = run_app_test('test1', stdout=self.devnull.fileno())
    time.sleep(0.1)

  def tearDown(self):
    self.process.kill()
    for f in self.tgts:
      if os.path.isfile(f):
        os.remove(f)
      elif os.path.isdir(f):
        shutil.rmtree(f)

  def _make_tgt_dir(self):
    tgt = tempfile.mkdtemp()
    self.tgts.append(tgt)
    return tgt

  def _make_tgt_file(self):
    fd, tgt = tempfile.mkstemp()
    os.close(fd)
    self.tgts.append(tgt)
    return tgt

  def test_dumptype_dir(self):
    tgt1 = self._make_tgt_dir()
    tgt2 = self._make_tgt_dir()
    tgt3 = self._make_tgt_dir()

    out1 = memory_dumper.dump(self.process.pid, tgt1, "dir", False, True)
    self.assertEquals(out1, tgt1) # same name

    self._renew_process()
    out2 = memory_dumper.dump(self.process.pid, tgt2, "dir", True, True)
    self.assertEquals(out2, tgt2) # same name

    self._renew_process()
    out3 = memory_dumper.dump(self.process.pid, tgt3, "dir", False, False)
    self.assertEquals(out3, tgt3) # same name

    size1 = get_folder_size(tgt1)
    size2 = get_folder_size(tgt2)
    size3 = get_folder_size(tgt3)

    self.assertGreater(size1, 500) # not a null archive
    self.assertGreater(size2, size1) # more mappings
    self.assertGreater(size3, size2) # more mappings
    
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

  def _test_type_file(self, typ):
    tgt1 = self._make_tgt_file()
    tgt2 = self._make_tgt_file()
    tgt3 = self._make_tgt_file()

    out1 = memory_dumper.dump(self.process.pid, tgt1, typ, False, True)
    self.assertEquals(out1, tgt1) # same name

    self._renew_process()
    out2 = memory_dumper.dump(self.process.pid, tgt2, typ, True, True)
    self.assertEquals(out2, tgt2) # same name

    self._renew_process()
    out3 = memory_dumper.dump(self.process.pid, tgt3, typ, False, False)
    self.assertEquals(out3, tgt3) # same name

    size1 = os.path.getsize(tgt1)
    size2 = os.path.getsize(tgt2)
    size3 = os.path.getsize(tgt3)

    self.assertGreater(size1, 500) # not a null archive
    self.assertGreater(size2, size1) # more mappings
    self.assertGreater(size3, size2) # more mappings

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

  def test_dumptype_tar(self):
    self._test_type_file("tar")
    return 

  def test_dumptype_gztar(self):
    self._test_type_file("gztar")
    return 


if __name__ == '__main__':
    unittest.main(verbosity=2)


