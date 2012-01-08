#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import subprocess
import sys
import shutil
import time

from test.run_src_app import run_app_test
from haystack import memory_dumper

log=logging.getLogger('cpp')

def main():
  fn = file('/dev/null')
  for app in ["./test-ctypes1", "./test-ctypes2", "./test-ctypes3"]:
    dumpname = app+'.dump'
    try:
      shutil.rmtree(dumpname)
    except:
      pass
    time.sleep(0.5) # load all the ldso
    pid1 = subprocess.Popen([app], stdout=fn.fileno())
    memory_dumper.dump(pid1.pid, dumpname)
    pid1.kill()


if __name__ == '__main__':
  main()

