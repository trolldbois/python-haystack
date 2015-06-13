#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setuptools scripts."""

from setuptools import setup

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


import distutils.cmd
import distutils.log
import subprocess


class PyPrepTestsCommand(distutils.cmd.Command):
    """A custom command to build test sets."""

    description = 'Run tests and dumps memory'
    user_options = []
    #    # The format is (long option, short option, description).
    #    ('pylint-rcfile=', None, 'path to Pylint config file'),
    #]

    def initialize_options(self):
        """Set default values for options."""
    #  # Each user option must be listed here with their default value.
    #  self.pylint_rcfile = ''
        pass

    def finalize_options(self):
        """Post-process options."""
    #  if self.pylint_rcfile:
    #    assert os.path.exists(self.pylint_rcfile), (
    #        'Pylint config file %s does not exist.' % self.pylint_rcfile)
        pass

    def run(self):
        """Run command."""
        import os
        import sys
        os.getcwd()
        makeCmd = ['make']
        p = subprocess.Popen(makeCmd, stdout=sys.stdout, cwd='test/src/')
        p.wait()
        return p.returncode




setup(name="haystack",
    version="0.20",
    description="Search C Structures in a process' memory",
    long_description=open("README.rst").read(),

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
    keywords=["memory","analysis","forensics","struct","ptrace","reverse","heap"],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    packages = ["haystack", "haystack.gui", "haystack.reverse", 
                "haystack.structures", "haystack.outputters",
                "haystack.structures.libc", "haystack.structures.win32"],
    #package_dir={"haystack.reverse": 'haystack/reverse'},
    package_data={"haystack.reverse": ['data/words.100'], },
    scripts = ["scripts/haystack", "scripts/haystack-gui", "scripts/haystack-dump", "scripts/haystack-reverse"],
    setup_requires=["numpy"], # https://github.com/numpy/numpy/issues/2434
    install_requires = ["ctypeslib2>2.1.3", "numpy", "networkx", "pefile", "python-ptrace", "python-Levenshtein"],
    dependency_links = ['https://github.com/trolldbois/ctypeslib/tarball/dev#egg=ctypeslib2-2.4beta'],
    #build_test_requires = ["ctypeslib2>=2.1.3"],
    test_suite= "test.alltests",
    #tests_require="haystack",
    #entry_points = {'haystack.plugins':['haystack.model:register']},
    cmdclass={
        'preptests': PyPrepTestsCommand,
    },
)


