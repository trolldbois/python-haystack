Getting started
===============

First you need to install python-haystack_. Please refer to the
:ref:`installation` section of the documentation.

Then you need a process memory dump. Please refer to the :ref:`capture-a-memory-dump`
section of the documentation.
We will name the process memory dump `memory.dmp` for the rest of this documentation.

*What is it all about?*

Yeti is about organizing observables, indicators of compromise, TTPs, and
knowledge on threat actors in a single, unified repository. Ideally, this
repository should be queryable in an automated way by other tools (spoiler:
it is!)

Malware stolen data
-------------------

You just analyzed the latest Dridex sample and you figured out that it's using
a subdirectory in the user's ``Roaming`` directory to store its data, and you'd
like to document this. *(Whether this is a strong indicator or not is another
story)*.

You start by adding a new **Entity** of type **Malware** called Dridex. Navigate
to **New > Malware**, and populate the fields.

Creating a Malware Entity
^^^^^^^^^^^^^^^^^^^^^^^^^