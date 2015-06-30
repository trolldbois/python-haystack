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
    time.sleep(1.9)
    #print('   **DUMP** ', pid1.pid)
    memory_dumper.dump(pid1.pid, dumpname)
    pid1.kill()
    out.close()
    if not os.access(app + ".stdout", os.F_OK):
        print "file %s was not written"%app + ".stdout"
        with file(app + ".stdout", 'w') as out:
            out.write('plop')
    return


if __name__ == '__main__':
    main()
