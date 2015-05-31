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
    install_requires = ["ctypeslib2>=2.1.3", "numpy", "networkx", "pefile", "python-ptrace", "python-Levenshtein"],
    dependency_links = ['https://github.com/trolldbois/ctypeslib/tarball/dev#egg=ctypeslib2-2.2beta'],
    #build_test_requires = ["ctypeslib2>=2.1.3"],
    test_suite= "test.alltests",
    #tests_require="haystack",
    #entry_points = {'haystack.plugins':['haystack.model:register']},
)


