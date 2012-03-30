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
  dumpname = sys.argv[1]
  fn = file('/dev/null')
  app = './%s'%(dumpname[:dumpname.rindex('.')])
  try:
    shutil.rmtree(dumpname)
  except:
    pass
  out = file(app+".stdout",'w')
  #pid1 = subprocess.Popen([app], stdout=fn.fileno())
  pid1 = subprocess.Popen([app], bufsize=-1, stdout=out.fileno())
  time.sleep(0.9) # 
  memory_dumper.dump(pid1.pid, dumpname)
  pid1.kill()

def mainold():
  fn = file('/dev/null')
  for app in ["./test-ctypes1", "./test-ctypes2", "./test-ctypes3", "./test-ctypes4"]:
    dumpname = app+'.dump'
    try:
      shutil.rmtree(dumpname)
    except:
      pass
    out = file(app+".stdout",'w')
    #pid1 = subprocess.Popen([app], stdout=fn.fileno())
    pid1 = subprocess.Popen([app], bufsize=-1, stdout=out.fileno())
    time.sleep(0.9) # 
    print '   **DUMP**'
    memory_dumper.dump(pid1.pid, dumpname)
    pid1.kill()

#lines=file('/home/jal/Compil/python-haystack/test/src/test-ctypes4.stdout').readlines()
#offsets = [ (line.split(' ')[1], hex(int(line.split(' ')[2]))) for line in lines[1:]]
#[('vector_obj', '0x88a1008'), ('list_int', '0x88a1168'), ('list_obj', '0x88a1218'), ('vector_int', '0x88a1378'), ('vector_obj', '0x88a1398')]

if __name__ == '__main__':
  main()

