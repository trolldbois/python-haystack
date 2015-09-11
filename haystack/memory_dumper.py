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
from haystack.mappings.process import readProcessMappings

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('dumper')


def archiveTypes(s):
    """Validates TYPE args to check if the dump type is correct."""
    if s not in MemoryDumper.ARCHIVE_TYPES:
        raise ValueError
    return s


class MemoryDumper:
    """
    Dumps a process memory maps to a tgz
    """
    ARCHIVE_TYPES = ["dir", "tar", "gztar"]

    def __init__(self, pid, dest, archiveType="dir", compact=False):
        self._pid = pid
        self._dest = os.path.normpath(dest)
        self._archive_type = archiveType
        self._compact_dump = compact

    def getMappings(self):
        """Returns the MemoryMappings."""
        return self.mappings

    def connectProcess(self):
        """Connect the debugguer to the process and gets the memory _memory_handler
        metadata."""
        self.dbg = dbg.PtraceDebugger()
        self.process = self.dbg.addProcess(self._pid, is_attached=False)
        if self.process is None:
            log.error(
                "Error initializing Process debugging for %d" %
                self._pid)
            raise IOError
            # ptrace exception is raised before that
        self.mappings = readProcessMappings(self.process)
        log.debug('_memory_handler read. Dropping ptrace on pid.')
        return

    def dump(self, dest=None):
        """Dumps the source memory mapping to the target dump place."""
        if dest is not None:
            self._dest = os.path.normpath(dest)
        if self._archive_type == "dir":
            self._dump_to_dir()
        else:
            self._dump_to_file()
        return self._dest

    def _dump_to_dir(self):
        """Dump memory _memory_handler to files in a directory."""
        if os.path.isfile(self._dest):
            raise TypeError('target is a file. You asked for a directory dump. '
                            'Please delete the file.')
        if not os.access(self._dest, os.X_OK | os.F_OK):
            os.mkdir(self._dest)
        self._dump_all_mappings(self._dest)
        self._free_process()
        return

    def _dump_to_file(self):
        """Dump memory _memory_handler to an archive."""
        if os.path.isdir(self._dest):
            raise TypeError('Target is a dir. You asked for a file dump. '
                            'Please delete the dir.')
        tmpdir = tempfile.mkdtemp()
        self._dump_all_mappings(tmpdir)
        self._free_process()
        self._make_archive(tmpdir, self._dest)
        return

    def _dump_all_mappings_winapp(self, destdir):
        # winappdbg
        self.index = file(os.path.join(destdir, 'mappings'), 'w+')
        # test dump only the heap
        err = 0
        memory_maps = self.process.generate_memory_snaphost()
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
        self.index = file(os.path.join(destdir, 'mappings'), 'w+')
        # test dump only the heap
        err = 0
        # print '\n'.join([str(m) for m in self._memory_handler])
        if self._compact_dump:
            finder = self.mappings.get_heap_finder()
            self.__required = finder.get_heap_mappings()
            # FIXME
            self.__required.append(self.mappings.get_stack())
        for m in self.mappings:
            try:
                self._dump_mapping(m, destdir)
            except IOError as e:
                err += 1
                log.warning(e)
                pass  # no se how to read windows
        log.debug('%d mapping in error, destdir: %s', err, destdir)
        self.index.close()
        return

    def _free_process(self):
        """continue() the process."""
        self.process.cont()
        self.dbg.deleteProcess(process=self.process)
        self.dbg.quit()
        return

    def _dump_mapping(self, m, tmpdir):
        """Dump one mapping to one file in one tmpdir."""
        my_utils = self.mappings.get_ctypes_utils()
        if m.permissions[0] != 'r':
            log.debug('Ignore read protected mapping %s', m)
            return
        elif m.pathname in ['[vdso]', '[vsyscall]']:
            log.debug('Ignore system mapping %s', m)
            return
        # make filename
        # We don't really care about the filename but we need to be coherent.
        mname = b'%s-%s' % (my_utils.formatAddress(m.start),
                            my_utils.formatAddress(m.end))
        mmap_fname = os.path.join(tmpdir, mname)
        # dumping the memorymap content if required.
        if self._compact_dump:
            # only dumps useful ( stack, heap, binary for arch detection
            if m in self.__required:
                with open(mmap_fname, 'wb') as mmap_fout:
                    mmap_fout.write(m.mmap().get_byte_buffer())
                log.debug('Dump %s', m)
            else:
                log.debug('Ignore %s', m)
        else:
            # dump all the maps
            log.debug('Dump %s', m)
            with open(mmap_fname, 'wb') as mmap_fout:
                mmap_fout.write(m.mmap().get_byte_buffer())
        # dump all the metadata
        self.index.write('%s\n' % m)
        return

    def _make_archive(self, srcdir, name):
        """Make an archive file."""
        log.debug('Making a archive ')
        tmpdir = tempfile.mkdtemp()
        tmpname = os.path.join(tmpdir, os.path.basename(name))
        log.debug('running shutil.make_archive')
        archive = shutil.make_archive(tmpname, self._archive_type, srcdir)
        shutil.move(archive, name)
        shutil.rmtree(tmpdir)
        shutil.rmtree(srcdir)
        return


def dump(pid, outfile, typ="dir", compact=False):
    """Dumps a process memory _memory_handler to Haystack dump format."""
    dumper = MemoryDumper(pid, outfile, typ, compact)
    dumper.connectProcess()
    destname = dumper.dump()
    log.info('Process %d memory _memory_handler dumped to file %s', dumper._pid, destname)
    return destname

def _dump(opt):
    """Dumps a process memory _memory_handler to Haystack dump format."""
    return dump(opt.pid, opt.dumpname, opt.type)

def argparser():
    dump_parser = argparse.ArgumentParser(prog='memory_dumper',
                                          description="dump a pid's memory to file.")
    dump_parser.add_argument('pid', type=int, action='store',
                             help='Target PID.')
    dump_parser.add_argument('--compact', action='store_const', const=True,
                             help='Only dump a small number of maps '
                                  '(heap,stack,exec).')
    dump_parser.add_argument('--type', type=archiveTypes, action='store',
                             default="dir",
                             help='Dump in "gztar","tar" or "dir" format. '
                                  'Defaults to "dir".')
    dump_parser.add_argument('dumpname', action='store', help='The dump name.')
    dump_parser.set_defaults(func=_dump)

    return dump_parser

def main(argv):
    logging.basicConfig(level=logging.DEBUG)
    parser = argparser()
    opts = parser.parse_args(argv)
    opts.func(opts)

if __name__ == '__main__':
    main(sys.argv[1:])
