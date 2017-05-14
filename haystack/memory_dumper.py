#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Dumps a process memory _memory_handler to a haystack dump format."""

import logging
import argparse
import shutil
import sys
import tempfile

import os
from haystack import dbg
from haystack.mappings.process import make_process_memory_handler

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('dumper')


class MemoryDumper:
    """
    Dumps a process memory maps to a tgz
    """
    ARCHIVE_TYPES = ["dir", "tar", "gztar"]

    def __init__(self, pid, dest):
        self._pid = pid
        self._dest = os.path.normpath(dest)
        self.dbg = None
        self._memory_handler = None

    def make_mappings(self):
        """Connect the debugguer to the process and gets the memory mappings
        metadata."""
        self.dbg = dbg.get_debugger(self._pid)
        self._memory_handler = make_process_memory_handler(self.dbg.get_process())
        log.debug('Memory Mappings read. Dropping ptrace on pid.')
        return

    def dump(self, dest=None):
        """Dumps the source memory mapping to the target dump place."""
        if dest is not None:
            self._dest = os.path.normpath(dest)
        if os.path.isfile(self._dest):
            raise TypeError('target is a file. You asked for a directory dump. '
                            'Please delete the file.')
        if not os.access(self._dest, os.X_OK | os.F_OK):
            os.mkdir(self._dest)
        self._dump_all_mappings(self._dest)
        self._free_process()
        return

    def _dump_all_mappings_winapp(self, destdir):
        # TODO TEST
        # winappdbg
        self.index = open(os.path.join(destdir, 'mappings'), 'w+')
        # test dump only the heap
        err = 0
        memory_maps = self.dbg.get_process().generate_memory_snaphost()
        for mbi in memory_maps:
            # TODO
            try:
                self._dump_mapping(mbi, destdir)
            except IOError as e:
                err += 1
                log.warning(e)
                pass  # no se how to read windows
        log.debug('%d mapping in error, destdir: %s', err, destdir)
        self.index.close()
        return

    def _dump_all_mappings(self, destdir):
        """Iterates on all _memory_handler and dumps them to file."""
        self.index = open(os.path.join(destdir, 'mappings'), 'w+')
        err = 0
        for m in self._memory_handler:
            try:
                self._dump_mapping(m, destdir)
            except IOError as e:
                err += 1
                log.warning(e)
                pass
        log.debug('%d mapping in error, destdir: %s', err, destdir)
        self.index.close()
        return

    def _free_process(self):
        """continue() the process."""
        self.dbg.quit()
        return

    def _dump_mapping(self, m, tmpdir):
        """Dump one mapping to one file in one tmpdir."""
        my_utils = self._memory_handler.get_target_platform().get_target_ctypes_utils()
        if m.permissions[0] != 'r':
            log.debug('Ignore read protected mapping %s', m)
            return
        elif m.pathname in ['[vdso]', '[vsyscall]', '[vvar]']:
            log.debug('Ignore system mapping %s', m)
            return
        # make filename
        # We don't really care about the filename but we need to be coherent.
        mname = b'%s-%s' % (my_utils.formatAddress(m.start), my_utils.formatAddress(m.end))
        mmap_fname = os.path.join(tmpdir, mname)
        # dumping the memorymap
        log.debug('Dump %s', m)
        with open(mmap_fname, 'wb') as mmap_fout:
            try:
                mmap_fout.write(m.mmap().get_byte_buffer())
            except Exception as e:
                raise IOError(e)
        # dump all the metadata
        start = my_utils.formatAddress(m.start)
        end =  my_utils.formatAddress(m.end)
        perms = m.permissions
        offset = '0x%0.8x' % m.offset
        device = '%0.2x:%0.2x' % (m.major_device, m.minor_device)
        inode = '%0.7d' % m.inode
        text = ' '.join([start, end, perms, offset, device, inode, str(m.pathname)])
        self.index.write('%s\n' % text)
        return


def dump(pid, outfile):
    """Dumps a process memory to Haystack dump format."""
    dumper = MemoryDumper(pid, outfile)
    dumper.make_mappings()
    dumper.dump()
    log.info('Process %d memory dumped to folder %s', pid, outfile)
    return outfile


def _dump(opt):
    """Dumps a process memory _memory_handler to Haystack dump format."""
    return dump(opt.pid, opt.dumpname)


def argparser():
    dump_parser = argparse.ArgumentParser(prog='memory_dumper',
                                          description="dump a pid's memory to file.")
    dump_parser.add_argument('pid', type=int, action='store',
                             help='Target PID.')
    dump_parser.add_argument('dumpname', action='store', help='The dump name.')
    dump_parser.set_defaults(func=_dump)

    return dump_parser


def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparser()
    opts = parser.parse_args(sys.argv[1:])
    opts.func(opts)
