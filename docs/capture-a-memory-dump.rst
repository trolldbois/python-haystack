.. _capture-process-memory:

Capture a process memory to file
================================

First of all, be prepared to face a need for elevated privileges.

On Windows, the most straightforward is to get a Minidump. The Windows task manager
allows to capture a process memory to file. Alternatively the Microsoft Sysinternals
suite of tools provide either a CLI (procdump.exe) or a GUI (Process explorer).
Using one of these (with full memory dump option) you will produce a file
that can be used with the ``haystack-xxx`` list of entry points using the ``dmp://``
file prefix.

While technically you could use many third party tool, Haystack actually
need memory mapping information to work with the raw memory data.
In nothing else, there is a dumping tool included in the pytahon-haystack package that
leverage python-ptrace to capture a process memory. See the ``haystack-live-dump`` tool:

.. code-block:: bash

    # haystack-live-dump <pid> myproc.dump

For live processes
------------------
 - ``haystack-live-dump`` capture a process memory dump to a folder (haystack format)

For a Rekall memory dump
------------------------
 - ``haystack-rekall-dump`` dump a specific process to a haystack process dump

For a Volatility memory dump
----------------------------
 - ``haystack-volatility-dump`` dump a specific process to a haystack process dump

Interesting note for Linux users, dumping a process memory for the same user can be done
if you downgrade the "security" of your system by allowing cross process ptrace access::

  $ sudo sysctl kernel.yama.ptrace_scope=0

Interesting note for Windows users, most processes memory can be dumped to a Minidump format
using the task manager. (NB: I don't remember is the process memory mapping are included then)

Making your own memory mappings handler
=======================================

If you have a different technique to access a process memory, you can implement the
``haystack.abc.IMemoryLoader`` and ``haystack.abc.IMemoryMapping`` interface for
your favorite technique.
Check out the `Frida plugin <https://github.com/trolldbois/python-haystack/blob/master/haystack/mappings/fridaprocess.py>`_
for example.

Alternatively, if you can copy the process' memory mappings to file, you can "interface"
with the basic, simple, haystack memory dump file format by doing the following:
The basic format is a folder containing each memory mapping in a separate file :
  - memory content in a file named after it's start/end addresses ( ex: 0x000700000-0x000800000 )
  - a file named 'mappings' containing memory mappings metadata.  ( ex: mappings )
