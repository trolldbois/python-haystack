.. python haystack documentation master file

Welcome to Haystack's documentation!
====================================

**Useful links**

* `Code repository <https://github.com/trolldbois/python-haystack>`_

Summary:
--------

Haystack is a framework dedicated to process heap analysis. The general idea
is that process memory contains user data (the interesting stuff) allocated by
the process and system metadata allocated by the kernel (in short) to manage
allocation and de-allocation of user data (as on of many metadata present in there)

This framework assists its user in a programmatic interpretation of the system
allocation metadata, so that the user can then concentrate on interpretation of
the user-data itself.

This framework also provide a way to search user allocated memory for specific
instance of user defined types such as C records. That mechanism is used internally
to identify the system metadata records used by the memory allocator to manage
allocation of user memory.

The framework also provide a way to reverse engineer the types of memory structure
in use by a process. The reversed types will take into account linked list, pointers
and other value constraints to propose a list of type definition.

Packages:
---------

The core package python-haystack_ is providing the base modules and classes to
search for instance of C records in a process memory.
Based on types definition (using python ctypes) and value constraints defined
by the user, the package allows to search a process memory for such instances.

The additional package python-haystack-reverse_ is providing a set of tools to
assist in reversing the types used by a process and recreate type definitions.

Contents:
---------

.. toctree::
  installation
  usage
  capture-process-memory

.. _python-haystack: https://github.com/trolldbois/python-haystack/
.. _python-haystack-reverse: https://github.com/trolldbois/python-haystack-reverse/
.. _python-haystack-gui: https://github.com/trolldbois/python-haystack-gui/
.. _python-haystack-docs: https://github.com/trolldbois/python-haystack-docs/
