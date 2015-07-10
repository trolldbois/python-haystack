# -*- coding: utf-8 -*-
#
# Copyright (C) 2011,2012,2013 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
Defines
        LoadableMembers
        LoadableMembersStructure
        LoadableMembersUnion
        CString.

        helpers function to import structures or to create duplicate
Plain Old Python Objects from ctypes structures modules.

    NotValid(Exception)
    LoadException(Exception)
"""
import importlib
from haystack import target

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

import inspect
import sys
import logging

log = logging.getLogger('model')


class _book(object):

    """The book registers all registered ctypes modules """

    def __init__(self):
        self.modules = set()
    """holds registered modules."""

    def addModule(self, mod):
        self.modules.add(mod)

    def getModules(self):
        return set(self.modules)

class NotValid(Exception):
    pass

class LoadException(Exception):
    pass

# FIXME
# this all class is useless. the create_POPO_classes should be a static helper somewhere else.
class Model(object):

    def __init__(self, memory_handler):
        self._memory_handler = memory_handler
        self._ctypes = self._memory_handler.get_target_platform().get_target_ctypes()
        self.__book = _book()

    def reset(self):
        """Clean the book"""
        log.info('RESET MODEL')
        self.__book.modules = set()
        for mod in sys.modules.keys():
            if 'haystack.reverse' in mod:
                del sys.modules[mod]
                log.debug('de-imported %s',mod)

    def __create_POPO_classes(self, targetmodule):
        """ Load all model classes and create a similar non-ctypes Python class
            thoses will be used to translate non pickable ctypes into POPOs.

            Mandatory.
        """
        _created = 0
        for name, klass in inspect.getmembers(targetmodule, inspect.isclass):
            if issubclass(
                    klass, self._ctypes.LoadableMembers) and klass is not self._ctypes.LoadableMembers:
                # Why restrict on module name ?
                # we only need to register loadablemembers (and basic ctypes ? )
                # if klass.__module__.startswith(targetmodule.__name__):
                from haystack.outputters import python
                kpy = type(
                    '%s.%s_py' %
                    (targetmodule.__name__, name), (python.pyObj,), {})
                # add the structure size to the class
                if issubclass(klass, self._ctypes.LoadableMembers):
                    log.debug(klass)
                    setattr(kpy, '_len_', self._ctypes.sizeof(klass))
                else:
                    setattr(kpy, '_len_', None)
                # we have to keep a local (model) ref because the class is being created here.
                # and we have a targetmodule ref. because it's asked.
                # and another ref on the real module for the basic type, because,
                # that is probably were it's gonna be used.
                setattr(
                    sys.modules[__name__], '%s.%s_py' %
                    (targetmodule.__name__, name), kpy)
                # setattr(sys.modules[__name__], '%s_py'%(name), kpy )
                setattr(targetmodule, '%s_py' % (name), kpy)
                _created += 1
                # copy also to generated
                if klass.__module__ != targetmodule.__name__:
                    setattr(sys.modules[klass.__module__], '%s_py' % (name), kpy)
                    #log.debug("Created %s_py"%klass)
        log.debug(
            'created %d POPO types in %s' %
            (_created, targetmodule.__name__))
        return _created

    def build_python_class_clones(self, targetmodule):
        """Registers a module that contains ctypes records.

        Mandatory call that will be done by haystack scripts.

        Ctypes modules are not required to register themselves, as long as haystack
        framework does it.

        The only real action is to :
        - Creates Plain old python object for each ctypes record to be able to
        pickle/unpickle them later.
        """
        log.debug('registering module %s' % (targetmodule))
        if targetmodule in self.get_registered_modules():
            log.warning('Module %s already registered. Skipping.', targetmodule)
            return
        _registered = self.__create_POPO_classes(targetmodule)
        if _registered == 0:
            log.warning(
                'No class found. Maybe you need to model.copy_generated_classes ?')
        # register once per session.
        self.__book.addModule(targetmodule)
        log.debug('registered %d modules total', len(self.__book.getModules()))
        return

    def get_registered_modules(self):
        return self.__book.getModules()

    # FIXME remove ?
    def copy_generated_classes(self, src, dst):
        """Copies the ctypes Records of a module into another module.
        Is equivalent to "from src import *" but with less clutter.
        E.g.: Enum, variable and functions will not be imported.

        Calling this method is facultative.

        :param src : src module, generated
        :param dst : dst module
        """
        log.debug('copy classes %s -> %s' % (src.__name__, dst.__name__))
        copied = 0
        for (name, klass) in inspect.getmembers(src, inspect.isclass):
            if issubclass(klass, self._ctypes.LoadableMembers):
                log.debug("setattr(%s,%s,%s)" % (dst.__name__, name, klass))
                setattr(dst, name, klass)
                copied += 1
            else:
                log.debug("drop %s - %s" % (name, klass))
                pass
        log.debug('Loaded %d C structs from src %s' % (copied, src.__name__))
        log.debug(
            'There is %d members in src %s' %
            (len(
                src.__dict__),
                src.__name__))
        return


def import_module(module_name, _target=None):
    """
    Import the python ctypes module.

    :param module_name:
    :param _target:
    :return:
    """
    if _target is None:
        _target = target.TargetPlatform.make_target_platform_local()
    # save ctypes
    real_ctypes = sys.modules['ctypes']
    sys.modules['ctypes'] = _target.get_target_ctypes()
    if module_name in sys.modules:
        del sys.modules[module_name]
    my_module = None
    try:
        # try to load that module with our ctypes proxy
        my_module = importlib.import_module(module_name)
        # FIXME debug and TU this to be sure it is removed from modules
        if module_name in sys.modules:
            del sys.modules[module_name]
    finally:
        # always clean up
        sys.modules['ctypes'] = real_ctypes
    return my_module