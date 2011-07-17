#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

__doc__ = '''
  Find a C Struct in process memory.

Run as command line :

$ sudo haystack --pid 26725 sslsnoop.ctypes_openssh.session_state refresh 0xb8b70d18 > instance.pickled
$ sudo haystack --pid 26725 <your ctypes Structure > search > instance.pickled

Or as a Graphical GUI ( Qt4 )

$ haystack-gui

Run in a python script :
>>> import haystack
>>> pid = 12345
>>> haystack.findStruct( pid , sslsnoop.ctypes_openssh.session_state)
>>> haystack.findStruct( pid , ctypes_example.big_struct)

It's easy to add new structures (check ctypeslib or do it by hand or check sslsnoop on github)

a) Your class must extend haystack.model.LoadableMembers.
b) You must give your class a completed _fields_ (with one _ ), like all ctypes.Structure
c) You can add an expectedValues dict() to your class to refine your search
d) call model.registerModule(sys.modules[__name__])

Advanced use : You can override methods to fine tune some validation or loading

The global algoritm :
a) A ctypes structure is mapped at a memory address.
b) The method loadMembers id called.
c) The method isValid is called on self.
d) A validation test is done for each members, it's expected values and memory space validity (pointers) are tested.
    The validation does not recurse.
e) Each members is then 'loaded' to local space.
    If the value is a pointer or a model.LoadableMembers type, it's recursively Loaded. ( and validated).
    If the recursive loading fails, the calls fails. bye-bye.
f) see next offset, goto a)

GUI usage:
----------

You need to have a process memory dump :

$ sudo haystack-dump dump 26725 dumps/myssh.dump

Then you can open it in the GUI :

$ haystack-gui # ( and Ctrl-O , click click)
$ hasytack-gui --dumpfile dumps/myssh.dump

The dump file format is a simple tar containing each memory map :
* content in a file named after it's start/end addresses ( 0x000700000-0x000800000 )
* python haystack.model.MemoryMapping object pickled ( 0x000700000-0x000800000.pickled )

You can the search a structure into that memory mapping ( [heap] for now ).
You have to import your extensions before that ( try sslsnoop.ctypes_openssh ) to have them listed in the search dialog.


Extension examples :
---------------------
@ see sslsnoop in the Pypi repo. openssl and nss structures are generated.
@ see ctypes-kernel on my github. Linux kernel structure are generated. (VMM is abitch)S
'''

import abouchet 

findStruct = abouchet.findStruct
findStructInFile = abouchet.findStructInFile
refreshStruct = abouchet.refreshStruct

all =[
  findStruct,
  findStructInFile,
  refreshStruct,
]


