#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setuptools scripts."""

from setuptools import setup

import distutils.cmd
import distutils.log
import subprocess


class PyPrepTestsCommand(distutils.cmd.Command):
    """
    A custom command to build test sets.
    Requires ctypeslib2.
    """

    description = 'Run tests and dumps memory'
    user_options = []
    #    # The format is (long option, short option, description).
    #    ('pylint-rcfile=', None, 'path to Pylint _target_platform file'),
    # ]

    def initialize_options(self):
        """Set default values for options."""
    #  # Each user option must be listed here with their default value.
    #  self.pylint_rcfile = ''
        pass

    def finalize_options(self):
        """Post-process options."""
    #  if self.pylint_rcfile:
    #    assert os.path.exists(self.pylint_rcfile), (
    #        'Pylint _target_platform file %s does not exist.' % self.pylint_rcfile)
        pass

    def run(self):
        """Run command."""
        import os
        import sys
        os.getcwd()
        # all dump files are in .tgz
        makeCmd = ['make', '-d']
        p = subprocess.Popen(makeCmd, stdout=sys.stdout, cwd='test/src/')
        #makeCmd = ['make', '-f', 'Makefile.prep']
        #p = subprocess.Popen(makeCmd, stdout=sys.stdout, cwd='test/src/')
        p.wait()
        return p.returncode


setup(name="haystack",
      version="0.34",
      description="Search C Structures in a process' memory",
      long_description=open("README.md").read(),
      url="http://packages.python.org/haystack/",
      download_url="http://github.com/trolldbois/python-haystack/tree/master",
      license="GPL",
      classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        #"Development Status :: 5 - Production/Stable",
      ],
      keywords=["memory","analysis","forensics","record","struct","ptrace","reverse","heap", "lfh", "lal"],
      author="Loic Jaquemet",
      author_email="loic.jaquemet+python@gmail.com",
      packages=["haystack",
                "haystack.abc",
                "haystack.gui",
                "haystack.mappings",
                "haystack.outputters",
                "haystack.reverse",
                "haystack.reverse.heuristics",
                "haystack.search",
                "haystack.allocators",
                "haystack.allocators.libc",
                "haystack.allocators.win32"],
      #package_dir={"haystack.reverse": 'haystack/reverse'},
      package_data={"haystack.reverse.heuristics": ['data/words.100'],
                    "haystack.allocators.win32": ['win7heap32.constraints',
                                                  'win7heap64.constraints',
                                                  'winxpheap32.constraints',
                                                  'winxpheap64.constraints'],
                    "haystack.allocators.libc": ['libcheap.constraints']},
      entry_points={
          'console_scripts': [
              'haystack-search = haystack.cli:main_search',
              'haystack-show = haystack.cli:main_show',
              'haystack-reverse = haystack.cli:main_reverse',
              'haystack-live-dump = haystack.memory_dumper:main',
              'haystack-live-search = haystack.cli:live_search',
              'haystack-live-show = haystack.cli:live_show',
              # 'haystack-live-watch = haystack.cli:live_watch',
              'haystack-rekall-search = haystack.cli:rekall_search',
              'haystack-rekall-show = haystack.cli:rekall_show',
              'haystack-rekall-dump = haystack.cli:rekall_dump',
              'haystack-volatility-search = haystack.cli:volatility_search',
              'haystack-volatility-show = haystack.cli:volatility_show',
              'haystack-volatility-dump = haystack.cli:volatility_dump',
              'haystack-minidump-search = haystack.cli:minidump_search',
              'haystack-minidump-show = haystack.cli:minidump_show',
              'haystack-minidump-reverse = haystack.cli:minidump_reverse',
          ]
      },
      scripts=[ #"scripts/haystack",
               # "scripts/haystack-gui",
               #"scripts/haystack-dump",
               #"scripts/haystack-reverse",
               "scripts/haystack-find-heap.py"],
      # reverse: numpy is a dependency for reverse.
      # https://github.com/numpy/numpy/issues/2434
      # numpy is already installed in travis-ci
      ## setup_requires=["numpy"],
      # search: install requires only pefile, python-ptrace for memory-dump
      # reverse: install requires networkx, numpy, Levenshtein for signatures
      install_requires=["pefile",
                        "python-ptrace",
                        # reverse need these.
                        #"numpy",
                        #"networkx",
                        #"python-Levenshtein"
                        ],
      dependency_links=[#"https://github.com/trolldbois/ctypeslib/tarball/dev#egg=ctypeslib2-2.4beta",
                        "https://github.com/volatilityfoundation/volatility/tarball/master#egg=volatility-trunk",
                        "https://github.com/google/rekall/tarball/master#egg=rekall-trunk",
                        "https://github.com/erocarrera/pefile/archive/pefile-1.2.10-139.tar.gz"],
      # build_test_requires = ["ctypeslib2>=2.1.3"],
      test_suite= "test.alltests",
      # https://pythonhosted.org/setuptools/setuptools.html
      # prep_test requires ctypeslib2
      #tests_require=["volatility"],
      # tests_require=["ctypeslib2>2.1.3"],
      #entry_points = {'haystack.plugins':['haystack.model:register']},
      cmdclass={
          'preptests': PyPrepTestsCommand,
      },
)


