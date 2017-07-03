.. _usage:

Usage
=====

First you need to install python-haystack_. Please refer to the
:ref:`installation` section of the documentation.

Then you need a process memory dump. Please refer to the :ref:`capture-process-memory`
section of the documentation.
We will name the process memory dump `memory.dmp` for the rest of this documentation.

Command line usage
------------------

A few entry points exists for different purposes

 - ``haystack-find-heap`` allows to show details on Windows HEAP.
 - ``haystack-search`` allows to search for instance of types
 - ``haystack-show`` allows to show a specific formatted values of a type instance at a specific memory address

You can use the following URL to designate your memory handler/dump:

 - ``dir:///path/to/my/haystack/fump/folder`` to use the haystack dump format
 - ``dmp:///path/to/my/minidump/file`` use the minidump format (microsoft?)
 - ``frida://name_or_pid_of_process_to_attach_to`` use frida to access a live process memory
 - ``live://name_or_pid_of_process_to_attach_to`` ptrace a live process
 - ``rekall://`` load a rekall image
 - ``volatility://`` load a volatility image

API usage
---------

.. automodule:: haystack.search.api
   :members:

.. _python-haystack: https://github.com/trolldbois/python-haystack/
.. _python-haystack-reverse: https://github.com/trolldbois/python-haystack-reverse/
.. _python-haystack-gui: https://github.com/trolldbois/python-haystack-gui/
.. _python-haystack-docs: https://github.com/trolldbois/python-haystack-docs/
