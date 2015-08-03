# python-haystack memory forensics

[![Build Status](https://travis-ci.org/trolldbois/python-haystack.svg?branch=development)](https://travis-ci.org/trolldbois/python-haystack)
[![Coverage Status](https://coveralls.io/repos/trolldbois/python-haystack/badge.svg?branch=development)](https://coveralls.io/r/trolldbois/python-haystack?branch=development)
[![Code Health](https://landscape.io/github/trolldbois/python-haystack/development/landscape.svg?style=flat)](https://landscape.io/github/trolldbois/python-haystack/development)
[![pypi](https://img.shields.io/pypi/dm/haystack.svg)](https://pypi.python.org/pypi/haystack)

Quick Start:
============
[Quick usage guide](docs/docs/Haystack basic usage.ipynb) in the docs/ folder.

Introduction:
=============

python-haystack is an heap analysis framework, focused on classic
C structure matching.

The first class of algorithms gives the ability to search for known
structures in a live process's memory, or in a memory dump.

The second class of algorithms aims at giving a reverse engineering look
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

- content in a file named after it's start/end addresses ( 0x000700000-0x000800000 )
- 'mappings' file containing memory mappings metadata.  ( mappings )


Search for known structures:
============================

You need the python definition/ctypes structures of the known
structures.
An example would be sslsnoop, which provide python ctypes structures for
openssl and openssh structures.

Quick info:
 This demonstrate the ability to brute-force the search
 of a known structure, based on fields types assumptions or constraints.
 The magic is performed in the model.py module.
 The constraints are applied on the python ctypes structures by the
 'expectedValues' static field.

Command line example:
---------------------

For example, this will dump the session_state structures + pointed
children structures as an python object that we can play with.
Lets assume we have an ssh client or server as pid *4042*::

  $ sudo haystack --pid 4042 --pickled sslsnoop.ctypes_openssh.session_state search > instance.pickled
  $ sudo haystack --pid 4042 --pickled sslsnoop.ctypes_openssh.session_state refresh 0xb8b70d18 > instance.pickled
  $ sudo haystack --pid xxxx --pickled <your ctypes Structure> search > instance.pickled


Graphic example :
-----------------

There is also an attempt at a Graphical GUI ( Qt4 )
Dump the process, then you can open it in the GUI::

$ haystack-gui # ( and Ctrl-O , click click)
$ haystack-gui --dumpname dumps/myssh.dump

You can the search a structure from the heap of that memory mapping.

You have to import your extensions before that to have them listed in
the search dialog.

( *try sslsnoop.ctypes_openssh* )

Tip:
 As this is a beta version, sslsnoop is hard-imported in the GUI.
 You should have it installed.


python script interpreter example:
----------------------------------

as root::

  >>> import haystack
  >>> state_it = haystack.search_process('sslsnoop.ctypes_openssh.session_state', 4042, hint=0)
  >>> state = state_it.next()[0][0]
  >>> state.receive_context.evp.app_data.aes_ctx.rd_key
  '\xcc\xeaM#\xbd# \xc1\x89\xf5\xaa\xb7\xc6f!\x91\xfe\x17\xcc\x97C4\xecV\xca\xc1F\xe1\x0c\xa7gp\xa0\x92\x9di\xe3\xa6q?)g7\xde%\xc0P\xae\x1e\xc1yV\xfdg\x08i\xd4\x00?\xb7\xf1\xc0o\x19\xaci\xad\xf7Q\x0e\xa5\x9e\x85\x0e\x9a)t\xce\xf507\x8f\xa9ef\x81\x0c\xfb\xe3\x8f\x96\xd2\x97Ac\xe2\x94t1\xed\xf2\xf5=\x16\x11z\xab\xc4\x86;\xc8&6\x9c\xc6\xa9\xc4i\xfb\xbf\xd5\x13P{S(\x98]\x82\xda\x8aDF\xb3q\xfb\x93\xa0!\x80\xc0\x88\xb9\xdd]\x8cK\xfe\x1b?:\x05\x88\x9f\x1b\x85H\x17\xa2X\x9b\xb6!\xac\x80\x89\x1b\xa9\x08\x16\x00,@\x01\xa2t\xd5LC\x7f\xdc\xa3\xfc5\xc3\xc1\xa8\xb3\xdcul\xfca\xfaG\xd7\x85r\xf1\x92\x93\xd5cn\xefa\xa5\x88l\xd0#\xfb2\x00H\xdc%\xed^\xdf\xa1\x86yFK\xaf\xcd\xe7)\xb2\xdd\xcb\xd1\xa8\xad\xb0\xdf\xb1\xb8E'

and that was the session key of the receive stream.


Extensibility:
--------------

It's easy to add new structures. Its basically the ctypes definition of
C structures that should be done following the next 4 steps :

#) Your class must extend haystack.model.LoadableMembersStructure.
#) You must give your class a completed _fields_ (with one _ ), like all ctypes.Structure
#) *Optional* You can add an expectedValues dict() to your ctype classes to add some constraints.
#) *Optional* You can override isValid and load_members to implement advanced constraints validation.
#) call model.build_python_class_clones(sys.modules[__name__])

Easy 'creation':
  use h2xml and xml2py binaries, shipped with ctypeslib to generate a python module from
  a C header.

Advanced use:
  You can override methods isValid and load_members to implements
  advanced data loading and constraints validation.

  See sslsnoop for loading cipher structures from void pointers

The global algorithm :
  #) The ctypes structure is mapped at the first offset of the memory
     mapping.
  #) The method load_members is called.
  #) The method isValid is called on self.
  #) A validation test is done for each members, constraints and
     memory space validity (pointers) are tested.
     The validation does not recurse.
  #) Each members is then 'loaded' to local space.
     If the value is a pointer or a model.LoadableMembersStructure type, it's
     recursively Loaded. ( and validated).
     If the recursive loading fails, the calls fails. bye-bye.
  #) If all contraints are respected, we have a match.
  #) Move to see next offset, goto 1)


Heap analysis / MemoryHandler Reverser / MemoryHandler forensics:
===================================================

Quick info:
 This tool parse the heap for allocator structures, pointers
 values, small integers and text (ascii/utf).
 Given all the previous information, it can extract instances
 and helps you in classifying and defining structures types.

::

|    usage: haystack-reverser [-h] [--debug]
|                             dumpname
|                             {instances,typemap,group,parent,graph,show,makesig,clean}
|                             ...
|
|    Several tools to reverse engineer structures on the heap.
|
|    positional arguments:
|      dumpname              Source memory dump by haystack.
|      {instances,typemap,group,parent,graph,show,makesig,clean}
|                            sub-command help
|        instances           List all structures instances with virtual address,
|                            member types guess and info.
|        typemap             Try to reverse generic types from instances'
|                            similarities.
|        group               Show structure instances groups by size and signature.
|        parent              Print the parent structures pointing to the structure
|                            located at this address.
|        graph               DISABLED - Show sorted structure instances groups by
|                            size and signature in a graph.
|        show                Show one structure instance.
|        makesig             Create a simple signature file of the heap - NULL,
|                            POINTERS, OTHER VALUES.
|        clean               Clean the memory dump from cached info.
|
|    optional arguments:
|      -h, --help            show this help message and exit
|      --debug               Debug mode on.


Command line example:
--------------------
This will create several files in the folder containing <yourdumpname>::

$ python haystack-reverse instances <yourdumpname>

The most interesting one being the <yourdumpname>.headers_values.py that
gives you an ctypes listing of all found structures, with gestimates
on fields types.

A <yourdumpname>.gexf file is also produced to help you visualize
instances links. It gets messy for any kind of serious application.


Show ordered list of structures, by similarities::

$ python haystack-reverse show <yourdumpname>

Show only structures of size *324*::

$ python haystack-reverse show --size 324 <yourdumpname>


Write to file an attempt to reversed the original types hierachy::

$ python haystack-reverse typemap <yourdumpname>


Extension examples :
====================
@ see sslsnoop in the Pypi repo. openssl and nss structures are generated.

@ see ctypes-kernel on my github. Linux kernel structure are generated from a build kernel tree. (VMM is abitch)


Pseudo Example for extension :
==============================

::

|from haystack.model import LoadableMembersStructure, RangeValue, NotNull
|
|class OpenSSLStruct(LoadableMembersStructure):
|  pass
|
|class RSA(OpenSSLStruct):
|  ''' rsa/rsa.h '''
|  _fields_ = [
|  ("pad",  ctypes.c_int),
|  ("version",  ctypes.c_long),
|  ("meth",ctypes.POINTER(BIGNUM)),#const RSA_METHOD *meth;
|  ("engine",ctypes.POINTER(ENGINE)),#ENGINE *engine;
|  ('n', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
|  ('e', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
|  ('d', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
|  ('p', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
|  ('q', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
|  ('dmp1', ctypes.POINTER(BIGNUM) ),
|  ('dmq1', ctypes.POINTER(BIGNUM) ),
|  ('iqmp', ctypes.POINTER(BIGNUM) ),
|  ("ex_data", CRYPTO_EX_DATA ),
|  ("references", ctypes.c_int),
|  ("flags", ctypes.c_int),
|  ("_method_mod_n", ctypes.POINTER(BN_MONT_CTX) ),
|  ("_method_mod_p", ctypes.POINTER(BN_MONT_CTX) ),
|  ("_method_mod_q", ctypes.POINTER(BN_MONT_CTX) ),
|  ("bignum_data",ctypes.POINTER(ctypes.c_ubyte)), ## moue c_char_p ou POINTER(c_char) ?
|  ("blinding",ctypes.POINTER(BIGNUM)),#BN_BLINDING *blinding;
|  ("mt_blinding",ctypes.POINTER(BIGNUM))#BN_BLINDING *mt_blinding;
|  ]
|  expectedValues={
|    "pad": [0],
|    "version": [0],
|    "references": RangeValue(0,0xfff),
|    "n": [NotNull],
|    "e": [NotNull],
|    "d": [NotNull],
|    "p": [NotNull],
|    "q": [NotNull],
|    "dmp1": [NotNull],
|    "dmq1": [NotNull],
|    "iqmp": [NotNull]
|  }
|  def load_members(self, mappings, maxDepth):
|    print 'example'
|    if not LoadableMembersStructure.load_members(self, mappings, maxDepth):
|      log.debug('RSA not loaded')
|      return False
|    return True
|
|# register to haystack
|model.build_python_class_clones(sys.modules[__name__])
|
|#EOF


not so FAQ :
============

What does it do ?:
------------------
The basic functionnality is to search in a process' memory maps for a
specific C Structures.

The extended reverse engineering functionnality aims at reversing
structures from memory/heap analysis.

How do it knows that the structures is valid ? :
------------------------------------------------
You add some constraints ( expectedValues ) on the fields. Pointers are also a good start.

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
- winappdbg on win32
- python-numpy
- python-networkx
- python-levenshtein
- several others...

Others
------
http://ntinfo.biz/ xntsv32
