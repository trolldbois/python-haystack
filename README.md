# python-haystack memory forensics

[![Build Status](https://travis-ci.org/trolldbois/python-haystack.svg?branch=master)](https://travis-ci.org/trolldbois/python-haystack)
[![Coverage Status](https://coveralls.io/repos/trolldbois/python-haystack/badge.svg?branch=master&service=github)](https://coveralls.io/github/trolldbois/python-haystack?branch=master)
[![Code Health](https://landscape.io/github/trolldbois/python-haystack/development/landscape.svg?style=flat)](https://landscape.io/github/trolldbois/python-haystack/master)
[![pypi](https://img.shields.io/pypi/dm/haystack.svg)](https://pypi.python.org/pypi/haystack)

Quick Start:
============
[Quick usage guide](docs/Haystack basic usage.ipynb) in the docs/ folder.

Introduction:
=============

python-haystack is an heap analysis framework, focused on classic
C structure matching.

The first function/API is the SEARCH function.
 - It gives the ability to search for known record types in a process memory dump (or live process's memory)

**alpha-stage**
The second function/API is the REVERSE function.
 - It aims at giving a reverse engineering look
at a memory dump, focusing on reconstruction, classification of classic
C structures from memory. Heap analysis. Dynamic types definition.

How to get a memory dump:
=========================

While technically you could use a third party tool, haystack actually
need memory mapping information to work with.
So there is a dumping tool included::

    $ sudo haystack-dump dump <pid> dumps/myssh.dump

You can easily reproduce the format of the dump, its a folder/archive
containing each memory map in a separate file :

- memory content in a file named after it's start/end addresses ( 0x000700000-0x000800000 )
- 'mappings' file containing memory mappings metadata.  ( mappings )

Or you can write a `haystack.abc.IMemoryMapping` implementation for your favorite format.
There is already a beta volatility support in `haystack.mappings.vol`

Search for known structures:
============================

To search for a specific record, you will first need to define that record type.
A [quick usage guide](docs/Haystack basic usage.ipynb) is available to go
over the basic steps to go from a C Header file to a Python ctypes definition.
Or you can do it yourself, with traditional Python ctypes records.

The search api is available through the `haystack` script but also in an API so 
that you can embed that search in your own code. 

In short, the haystack search will iterate over every offset of the program's 
memory to try and find 'valid' offset for that specific record type.

The validity of the record  is determined mostly by inherent constraints, like
pointer values that should be in a valid address space, or your own constraints 
that you define in a file.

You can take a look a `haystack/structures/win32/winxpheap.constraints`, where
the constraints of a Windows XP HEAP are defined.

Obviously, the more constraints, the better the results will be.  

Constraints file:
-----------------

The following constraints are supported:
 - IgnoreMember: The value of this field will be ignored. Useful to Ignore pointer fields.
 - NotNull: The value of this field must not be 0.
 - RangeValue(x,y): the field must have a value between x and y.
 - PerfectMatch('hello world'): the field (a string) must match 'hello world'
 - [1,2,3]: A list of values that the fields should have
 - [1, RangeValue(12,16), 42]: The field value should be 1, 12-16 or 42.


Example:

    [struct_name]
    myfield: [1,0xff]
    ptr_field: NotNull


Command line example:
---------------------

**sslsnoop repository needs an update to be compatible with releases > v0.20 - pending** 

For example, this will dump the session_state structures + pointed
children structures as an python object that we can play with.
Lets assume we have an ssh client or server as pid *4042*:

    $ sudo haystack --pid 4042 --pickled sslsnoop.ctypes_openssh.session_state search > instance.pickled
    $ sudo haystack --pid 4042 --pickled sslsnoop.ctypes_openssh.session_state refresh 0xb8b70d18 > instance.pickled
    $ sudo haystack --pid xxxx --pickled <your ctypes Structure> search > instance.pickled


Graphic example :
-----------------

**This is not working right now**

There is also an attempt at a Graphical GUI ( Qt4 )
Dump the process, then you can open it in the GUI::

    $ haystack-gui # ( and Ctrl-O , click click)
    $ haystack-gui --dumpname dumps/myssh.dump

You can the search a structure from the heap of that memory mapping.

You have to import your extensions before that to have them listed in
the search dialog.


python API example:
----------------------------------

See the [quick usage guide](docs/docs/Haystack basic usage.ipynb)


How to define your own structures:
--------------

The most easy way is to use ctypeslib to generate ctypes records from
C Headers.

Or define your python ctypes record by hand.


Heap analysis / MemoryHandler Reverser / MemoryHandler forensics:
===================================================

**alpha-stage-not-working** 

Quick info:
 The `haystack-reverse` tool parse the heap for allocator structures, pointers
 values, small integers and text (ascii/utf).
 Given all the previous information, it can extract instances
 and helps you in classifying and defining structures types.


Command line example:
--------------------
This will create several files in the folder containing <yourdumpname>:

    $ python haystack-reverse <yourdumpfolder> instances
    $ python haystack-reverse haystack/test/src/test-ctypes6.64.dump instances
    $ ls -l haystack/test/src/test-ctypes6.64.dump/cache
    $ ls -l haystack/test/src/test-ctypes6.64.dump/cache/structs

The most interesting one being the `<yourdumpfolder>/cache/headers_values.py` that
gives you an ctypes listing of all found structures, with guesstimates
on fields types.

A `<yourdumpfolder>/cache/graph.gexf` file is also produced to help you visualize
instances links. It gets messy for any kind of serious application.


Show ordered list of structures, by similarities:

    $ python haystack-reverse <yourdumpname> show

Show only structures of size *324*::

    $ python haystack-reverse <yourdumpname> show --size 324 


Write to file an attempt to reversed the original types hierachy:

    $ python haystack-reverse <yourdumpname> typemap 

Clean the cache created :

    $ python haystack-reverse <yourdumpname> clean 


Extension examples :
====================
@ see sslsnoop in the Pypi repo. openssl and nss structures are generated.

@ see ctypes-kernel on my github. Linux kernel structure are generated from a build kernel tree. (VMM is abitch)



not so FAQ :
============

What does it do ?:
------------------
The basic functionality is to search in a process' memory for a
specific C Record.

The extended reverse engineering functionality aims at reversing
structures from memory/heap analysis.

How do it knows that the structures is valid ? :
------------------------------------------------
You add some constraints on the record fields expected values. 
Pointers are always constrained to valid memory space.

Where does the idea comes from ? :
-----------------------------------
http://www.hsc.fr/ressources/breves/passe-partout.html.fr originally.
since I started in March 2011, I have uncovered several other related
previous work.

Most of them are in the docs/ folder.

Other related work are mona.py from Immunity, some other Mandiant stuff...

In a nutshell, this is probably not an original idea. But yet, I could
not find a operational standalone lib for live memory extraction for my sslsnoop PoC, so....


What are the dependencies ? :
----------------------------

- python-ptrace on linux
- winappdbg on win32 ( not sure if working, feedback welcome)
- python-numpy
- python-networkx
- python-levenshtein
- several others...

Others
------
http://ntinfo.biz/ xntsv32
