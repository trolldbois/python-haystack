#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import subprocess
import sys
import shutil
import time

from haystack import memory_dumper

log = logging.getLogger('make.py')


def main():
    print('   **make.py** ', sys.argv[1])
    dumpname = sys.argv[1]
    fn = open('/dev/null')
    app = './%s' % (dumpname[:dumpname.rindex('.')])
    print('   **make.py** app', app)
    try:
        print('   **cleantree** dumpname', dumpname)
        shutil.rmtree(dumpname)
        print('   **cleantree done** dumpname', dumpname)
    except:
        pass
    print('   **open stdout w** ', app + ".stdout")
    out = open(app + ".stdout", 'w')
    # pid1 = subprocess.Popen([app], stdout=fn.fileno())
    print('   **popen process** ', app)
    pid1 = subprocess.Popen([app], bufsize=-1, stdout=out.fileno())
    print("process", pid1.pid, "was launched")
    time.sleep(0.9)
    print("  **end sleep**", pid1.pid)
    if not os.access(app + ".stdout", os.F_OK):
        print(" ** preDUMP ** file %s was not written" % app + ".stdout")
    print('   **DUMP** ', pid1.pid)
    memory_dumper.dump(pid1.pid, dumpname)
    print('   **DUMP terminated** ', pid1.pid)
    print('   **KILL** ', pid1.pid)
    pid1.kill()
    print('   **KILL finished** ', pid1.pid)
    out.close()
    if not os.access(app + ".stdout", os.F_OK):
        print("file %s was not written" % app + ".stdout")
        with open(app + ".stdout", 'w') as out:
            out.write('plop')
    return


if __name__ == '__main__':
    main()
