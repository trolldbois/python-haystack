#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setuptools scripts."""

from setuptools import setup

import distutils.cmd
import distutils.log
import subprocess
import sys


class PyPrepTestsCommand(distutils.cmd.Command):
    """
    A custom command to build test sets.
    Requires ctypeslib2.
    """

    description = 'Run tests and dumps memory'
    user_options = []

    def initialize_options(self):
        """Set default values for options."""
        pass

    def finalize_options(self):
        """Post-process options."""
        pass

    def run(self):
        """Run command."""
        import os
        import sys
        os.getcwd()
        # all dump files are in .tgz
        make_cmd = ['make', '-d']
        p = subprocess.Popen(make_cmd, stdout=sys.stdout, cwd='test/src/')
        p.wait()
        return p.returncode


setup(name="haystack",
      version="0.42",
      description="Search C Structures in a process' memory",
      long_description=open("README.rst").read(),
      url="http://packages.python.org/haystack/",
      download_url="http://github.com/trolldbois/python-haystack/tree/master",
      license="GPL",
      classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production/Stable",
      ],
      keywords=["memory", "analysis", "forensics", "record", "struct", "ptrace", "heap", "lfh", "lal"],
      author="Loic Jaquemet",
      author_email="loic.jaquemet+python@gmail.com",
      packages=["haystack",
                "haystack.abc",
                "haystack.mappings",
                "haystack.outputters",
                "haystack.search",
                "haystack.allocators",
                "haystack.allocators.libc",
                "haystack.allocators.win32"],
      package_data={
            "haystack.allocators.win32": ['win7heap32.constraints',
                                          'win7heap64.constraints',
                                          'winxpheap32.constraints',
                                          'winxpheap64.constraints'],
            "haystack.allocators.libc": ['libcheap.constraints']},
      entry_points={
            'console_scripts': [
                'haystack-find-heap = haystack.cliwin:find_heap',
                'haystack-search = haystack.cli:search',
                'haystack-show = haystack.cli:main_show',
                'haystack-live-dump = haystack.memory_dumper:main',
                'haystack-live-watch = haystack.cli:live_watch',
                'haystack-rekall-dump = haystack.cli:rekall_dump',
                'haystack-volatility-dump = haystack.cli:volatility_dump',
            ],
            # memory mappings loader haystack.abc.interfaces.IMemoryLoader
            'haystack.mappings_loader': [
                'dir = haystack.mappings.folder:FolderLoader',
                'dmp = haystack.mappings.minidump:DMPLoader',
                'volatility = haystack.mappings.vol:VolatilityLoader',
                'rekall = haystack.mappings.rek:RekallLoader',
                'live = haystack.mappings.process:ProcessLoader',
                'frida = haystack.mappings.fridaprocess:FridaLoader',
                'cuckoo = haystack.mappings.cuckoo:CuckooProcessLoader',
            ],
            # HEAP parsing haystack.abc.interfaces.IHeapFinder
            'haystack.heap_finder': [
                'ptmalloc2 = haystack.allocators.libc.libcheapwalker.LibcHeapFinder',
                'winxp = haystack.allocators.win32.winxpheapwalker.WinXPHeapFinder',
                'win7 = haystack.allocators.win32.win7heapwalker.Win7HeapFinder',
            ]
      },
      # search: install requires only pefile, python-ptrace for memory-dump
      # reverse: install requires networkx, numpy, Levenshtein for signatures
      install_requires=["pefile",  # >=1.2.10_139
                        "construct<2.8",
                        ] + ["python-ptrace>=0.8.1"] if "win" not in sys.platform else []
                          + ["winappdbg"] if "win" in sys.platform else [],
      dependency_links=[
                        # "https://github.com/trolldbois/ctypeslib/tarball/dev#egg=ctypeslib2-2.4beta",
                        "https://github.com/volatilityfoundation/volatility/tarball/master#egg=volatility-trunk",
                        "https://github.com/google/rekall/tarball/master#egg=rekall-trunk",
                        # "https://github.com/erocarrera/pefile/archive/pefile-1.2.10-139.tar.gz"
                        ],
      test_suite="test.alltests",
      # https://pythonhosted.org/setuptools/setuptools.html
      # prep_test requires ctypeslib2
      # build_test_requires = ["ctypeslib2>=2.1.3"],
      # tests_require=["ctypeslib2>2.1.3"],
      cmdclass={
          'preptests': PyPrepTestsCommand,
      },
      )
