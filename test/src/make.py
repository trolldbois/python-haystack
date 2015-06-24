#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import subprocess
import sys
import shutil
import time

from haystack import memory_dumper

log = logging.getLogger('make.py')


def main():
    dumpname = sys.argv[1]
    fn = file('/dev/null')
    app = './%s' % (dumpname[:dumpname.rindex('.')])
    try:
        shutil.rmtree(dumpname)
    except:
        pass
    out = file(app + ".stdout", 'w')
    #pid1 = subprocess.Popen([app], stdout=fn.fileno())
    pid1 = subprocess.Popen([app], bufsize=-1, stdout=out.fileno())
    time.sleep(0.9)
    #print('   **DUMP** ', pid1.pid)
    memory_dumper.dump(pid1.pid, dumpname)
    pid1.kill()


if __name__ == '__main__':
    main()
