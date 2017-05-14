# /bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import os

"""
Transform volatility produce mappings to haystack's.

vol.py -f vol/zeus.vmem vaddump -p 856 --dump-dir vol/zeus.vmem.856.dump/ > vol/zeus.vmem.856.dump/mappings.vol
vol2map.py vol/zeus.vmem.856.dump/mappings.vol > vol/zeus.vmem.856.dump/mappings


Pid        Process              Start      End        Result
---------- -------------------- ---------- ---------- ------
       856 svchost.exe          0x01000000 0x01005fff /home/jal/outputs/vol/zeus.vmem.856.dump/svchost.exe.115b8d8.0x01000000-0x01005fff.dmp

Start      End        perm offset     dev   inode   pathname
0x08048000 0x0804a000 r-xp 0x00000000 08:01 4588529 /home/other/Compil/python-haystack/test/src/test-ctypes2.32
"""

def main(filename):
    with open(filename,'r') as fin:
        entries = fin.readlines()
        i_start = entries[0].index('Start')
        i_end = entries[0].index('End')
        i_path = entries[0].index('Result')
        fmt = b'0x%08x'
        if i_end - i_start > 12:
            fmt = b'0x%016x'
        for i, line in enumerate(entries[2:]):
            start = int(line[i_start:i_end].strip(), 16)
            end = int(line[i_end:i_path].strip(), 16) + 1
            path = line[i_path:].strip()
            o_path = "%s-%s" % (fmt % start, fmt % end)
            # rename file
            try:
                os.rename(path, o_path)
            except OSError as e:
                sys.stderr.write('File rename error\n')
            # offset is unknown.
            print('%s %s r-xp %s 00:00 %d [vol_mapping_%03d]' % (fmt % start, fmt % end, fmt % 0, 0, i))


if __name__ == '__main__':
    main(sys.argv[1])

