.. _installation:

Installation
============

These procedures were tested on Ubuntu 16.04.

Install from PyPi
-----------------

Install a virtual environment::

  $ virtualenv v_haystack
  $ source v_haystack/bin/activate

Install python-haystack::

  (v_haystack) $ pip install haystack

Keeping it up to date ::

  (v_haystack) $ pip install haystack --upgrade

Clone+Install from GitHub
-------------------------

Clone python-haystack::

  $ git clone https://github.com/trolldbois/python-haystack.git

Setup a virtual environment::

  $ virtualenv v_haystack
  $ source v_haystack/bin/activate

Install python-haystack (won't work otherwise)::

  (v_haystack) $ cd python-haystack
  (v_haystack) ~/python-haystack$ pip install -r requirements
  (v_haystack) ~/python-haystack$ python setup.py install

Keeping it up to date ::

  (v_haystack) $ cd python-haystack
  (v_haystack) ~/python-haystack$ git pull

