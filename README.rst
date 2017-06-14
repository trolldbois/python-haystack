# python-haystack memory forensics

[![Build Status](https://travis-ci.org/trolldbois/python-haystack.svg?branch=master)](https://travis-ci.org/trolldbois/python-haystack)
[![Coverage Status](https://coveralls.io/repos/trolldbois/python-haystack/badge.svg?branch=master&service=github)](https://coveralls.io/github/trolldbois/python-haystack?branch=master)
[![Code Health](https://landscape.io/github/trolldbois/python-haystack/master/landscape.svg?style=flat)](https://landscape.io/github/trolldbois/python-haystack/master)
[![pypi](https://img.shields.io/pypi/dm/haystack.svg)](https://pypi.python.org/pypi/haystack)

Quick Start:
============
[Quick usage guide](docs/Haystack_basic_usage.ipynb) in the docs/ folder.
[Haystack-reverse CLI](docs/Haystack_reverse_CLI.ipynb) in the docs/ folder.

Introduction:
=============

python-haystack is an heap analysis framework, focused on searching and reversing of
C structure in allocated memory.

The first function/API is the SEARCH function.
 - It gives the ability to search for known record types in a process memory dump or live process's memory.

The second function/API is the REVERSE function in the extension [python-haystack-reverse](https://github.com/trolldbois/python-haystack-reverse)
 - It aims at helping an analyst in reverse engineering the memory records types present in a process heap.
It focuses on reconstruction, classification of classic C structures from memory.
It attempts to recreate types definition.

Scripts & Entry Points:
=======================

A few entry points exists to handle the format your memory dump.

Memory dump folder produced by `haystack-live-dump`
---------------------------------------------------
 - `haystack-find-heap` allows to show details on Windows HEAP.
 - `haystack-search` search CLI
 - `haystack-show` show CLI for specific record type at a specific address

Memory dump file produced by a Minidump tool
---------------------------------------------------
 - `haystack-find-heap` allows to show details on Windows HEAP.
 - `haystack-minidump-search` search CLI
 - `haystack-minidump-show` show a specific record type at a specific address

For live processes
------------------
 - `haystack-live-dump` capture a process memory dump to a folder (haystack format)
 - `haystack-live-search` search CLI in live process memory
 - `haystack-live-show` show a specific record type at a specific addres in a live process memory

For a Rekall memory dump
---------------------------
 - `haystack-rekall-search` search CLI for a specific process in a rekall dump
 - `haystack-rekall-show` show a specific record type at a specific address
 - `haystack-rekall-dump` dump a specific process to a haystack process dump

For a Volatility memory dump
---------------------------
 - `haystack-volatility-search`  search CLI for a specific process in a volatility dump
 - `haystack-volatility-show` show a specific record type at a specific address
 - `haystack-volatility-dump` dump a specific process to a haystack process dump

How to get a memory dump:
=========================

On Windows, the most straightforward is to get a Minidump. The Microsoft Sysinternals
suite of tools provide either a CLI (procdump.exe) or a GUI (Process explorer).
Using one of these (with full memory dump option) you will produce a file
that can be used with the `haystack-minidump-xxx` list of entry points.

While technically you could use many third party tool, haystack actually
need memory mapping information to work with.
So there is a dumping tool included `haystack-live-dump`:

    # haystack-live-dump <pid> myproc.dump

You can easily reproduce the format of the dump, its a folder/archive
containing each memory map in a separate file :

- memory content in a file named after it's start/end addresses ( 0x000700000-0x000800000 )
- 'mappings' file containing memory mappings metadata.  ( mappings )

Or you can code a `haystack.abc.IMemoryMapping` implementation for your favorite format.

Otherwise, if you already have a system memory dump from Volatility or Rekall,
you can use the `haystack-rekall-xxx` or `haystack-volatility-xxx` families of
entry points to extract a specific process memory into a file.

Verifying Windows Heap attributes:
==================================

The entry point `haystack-find-heap` allows to show details on Windows HEAP.
It should support:

- Windows XP 32 bits
- Windows XP 64 bits
- Windows 7 32 bits
- Windows 7 64 bits

and show details of the Look Aside List (LAL) and Low Fragmentation Heap (LFH) frontend.

You might be surprised to see that sometimes, a single process can mix the two types of HEAP (32 & 64).

Search for known structures:
============================

To search for a specific record, you will first need to define that record type.
A [quick usage guide](docs/Haystack basic usage.ipynb) is available to go
over the basic steps to go from a C Header file to a Python ctypes definition.
Or you can do it yourself, with traditional Python ctypes records.

The search api is available through the `haystack-xxx-search` family of scripts but
also in an API so that you can embed that search in your own code.

In short, the haystack search will iterate over every offset of the program's
memory to try and find 'valid' offset for that specific record type.

The validity of the record is determined by type constraints such as:
- pointer field should have valid address space values
- user-defined type constraints (see 'Constraints file' section below)
- etc..

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

You can take a look a `haystack/allocators/win32/winxpheap32.constraints`, where
the constraints of a Windows XP HEAP x32 are defined.

Obviously, the more constraints, the better the results will be.

Dynamic constraints definition:
-------------------------------
You can also create more complex constraints using python code by implementing
a `haystack.abc.interface.IRecordTypeDynamicConstraintsValidator` class and feeding it to
the `ModuleConstraints.set_dynamic_constraints`

Command line example:
---------------------

**sslsnoop repository needs an update to be compatible with releases > v0.30 - pending**

For example, this will dump the session_state structures + pointed
children structures as an python object that we can play with.
Lets assume we have an ssh client or server as pid *4042*:

    $ sudo haystack-live-search --pickled 4042 sslsnoop.ctypes_openssh.session_state search > instance.pickled
    $ sudo haystack-live-search --pickled 4042 sslsnoop.ctypes_openssh.session_state refresh 0xb8b70d18 > instance.pickled
    $ sudo haystack-live-search --pickled <pid> <your ctypes Structure> search


Graphic User Interface :
------------------------

**This is not working right now**

There is also an attempt at a Graphical UI [python-haystack-gui](https://github.com/trolldbois/python-haystack-gui)


python API example:
-------------------

See the [quick usage guide](docs/Haystack_basic_usage.ipynb)


How to define your own structures:
----------------------------------

The most easy way is to use ctypeslib to generate ctypes records from
C Headers.

Or define your python ctypes record by hand.


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

[Related work](https://github.com/trolldbois/python-haystack/wiki/State-of-art-reference)

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
