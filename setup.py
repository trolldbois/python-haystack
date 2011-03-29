# -*- coding: utf-8 -*-
from setuptools import setup
from glob import glob

setup(name="haystack",
    version="0.2",
    description="Search C Structures in a process' memory",
    long_description="""
HOWTO:
------

>>> import haystack
>>> haystack.findStruct( pid , 'ctypes.c_int')
>>> haystack.findStruct( pid , 'ctypes_example.big_struct')

It's easy to add new structures (check ctypeslib or do it by hand )


not so FAQ :
============

What does it do ?:
------------------
The basic functionnality is to search in a process' memory maps for a specific C Structures.

How do it knows that the structures is valid ? :
------------------------------------------------
You add some constraints ( expectedValues ) on the fields. Pointers are also a good start.

    """,

    url="http://packages.python.org/haystack/",
    download_url="http://github.com/trolldbois/python-haystack/tree/master",
    license='GPL',
    classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=['memory','analysis','forensics','struct','ptrace'],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    packages = ['haystack'],
    extras_require = {
        'ptrace':  ["python-ptrace"],
    },
)
