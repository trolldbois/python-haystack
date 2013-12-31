#!/usr/bin/env python
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

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

import ctypes
import logging

log = logging.getLogger('model')

# The book registers all haystack modules, and classes, and can keep 
# some pointer refs on memory allocated within special cases...
# see ctypes._pointer_type_cache , _reset_cache()
class _book(object):
    modules = set()
    classes = dict()
    refs = dict()
    def __init__(self):
        pass
    def addModule(self, mod):
        self.modules.add(mod)
    def addClass(self,cls):
        # ctypes._pointer_type_cache is sufficient
        #self.classes[ctypes.POINTER(cls)] = cls
        ctypes.POINTER(cls)
    def addRef(self,obj, typ, addr):
        self.refs[(typ,addr)]=obj
    def getModules(self):
        return set(self.modules)
    def getClasses(self):
        return dict(self.classes)
    def getRef(self,typ,addr):
        if len(self.refs) > 35000:
            log.warning('the book is full, you should haystack.model.reset()')
        return self.refs[(typ,addr)]
    def delRef(self,typ,addr):
        del self.refs[(typ,addr)]
    def isRegisteredType(self, typ):
        return typ in self.classes.values()

        
# central model book register
__book = _book()

def reset():
    global __book
    __book.refs = dict()

def getRefs():
    return __book.refs.items()

def printRefs():
    l=[(typ,obj,addr) for ((typ,addr),obj) in __book.refs.items()]
    for i in l:
        print(l)

def printRefsLite():
    l=[(typ,addr) for ((typ,addr),obj) in __book.refs.items()]
    for i in l:
        print(l)

def hasRef(typ,origAddr):
    return (typ,origAddr) in __book.refs

def getRef(typ,origAddr):
    if (typ,origAddr) in __book.refs:
        return __book.getRef(typ,origAddr)
    return None

def getRefByAddr(addr):
    ret=[]
    for (typ,origAddr) in __book.refs.keys():
        if origAddr == addr:
            ret.append( (typ, origAddr, __book.refs[(typ, origAddr)] ) )
    return ret

def keepRef(obj,typ=None,origAddr=None):
    ''' Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object, 
        they might be transient (if obj == somepointer.contents).'''
    # TODO, memory leak for different objects of same size, overlapping struct.
    if (typ,origAddr) in __book.refs:
        # ADDRESS already in refs
        if origAddr is None:
            origAddr='None'
        else:
            origAddr=hex(origAddr)
        if typ is not None:
            log.debug('references already in cache %s/%s'%(typ,origAddr))
        return
    __book.addRef(obj,typ,origAddr)
    return

def delRef(typ,origAddr):
    ''' Forget about a Ref..'''
    if (typ,origAddr) in __book.refs:
        __book.delRef(typ,origAddr)
    return

def get_subtype(cls):
    if hasattr(cls, '_subtype_'):
        return cls._subtype_    
    return cls._type_    


#def register(klass):
#    #klass.classRef = __register
#    #__register[ctypes.POINTER(klass)] = klass
#    __book.addClass(klass)
#    #klass.classRef = __book.classes
#    #klass.classRef = ctypes._pointer_type_cache
#    # p_st._type_
#    return klass

def registeredModules():
    return sys.modules[__name__].__book.getModules()

class NotValid(Exception):
    pass

class LoadException(Exception):
    pass



import inspect,sys

def copyGeneratedClasses(src, dst):
    ''' 
        Copies the members of a generated module into a classic module.
        Name convention : 
        generated: ctypes_libraryname_generated.py
        classic    : ctypes_libraryname.py
        
    :param me : dst module
    :param src : src module, generated
    '''
    __root_module_name,__dot,__module_name = dst.__name__.rpartition('.')
    _loaded=0
    _registered=0
    for (name, klass) in inspect.getmembers(src, inspect.isclass):
        if issubclass(klass, ctypes.LoadableMembers): 
            #if klass.__module__.endswith('%s_generated'%(__module_name) ) :
                setattr(dst, name, klass)
                log.debug("setattr(%s,%s,%s)"%(dst.__name__,name, klass))
                _loaded+=1
        else:
            log.debug("drop %s - %s"%(name, klass))
            pass
    log.debug('loaded %d C structs from %s structs'%( _loaded, src.__name__))
    log.debug('registered %d Pointers types'%( _registered))
    log.debug('There is %d members in %s'%(len(src.__dict__), src.__name__))
    return 


def createPOPOClasses( targetmodule ):
    ''' Load all model classes and create a similar non-ctypes Python class    
        thoses will be used to translate non pickable ctypes into POPOs.
    '''
    from haystack import basicmodel
    _created=0
    for name,klass in inspect.getmembers(targetmodule, inspect.isclass):
        if issubclass(klass, ctypes.LoadableMembers) and klass is not ctypes.LoadableMembers: 
            # Why restrict on module name ?
            # we only need to register loadablemembers (and basic ctypes ? )
            #if klass.__module__.startswith(targetmodule.__name__):            
            kpy = type('%s.%s_py'%(targetmodule.__name__, name),( basicmodel.pyObj ,),{})
            # add the structure size to the class
            if issubclass(klass, ctypes.LoadableMembers ) : # FIXME doh
                log.debug(klass)
                setattr(kpy, '_len_',ctypes.sizeof(klass) )
            else:
                setattr(kpy, '_len_', None )
            # we have to keep a local (model) ref because the class is being created here.
            # and we have a targetmodule ref. because it's asked.
            # and another ref on the real module for the basic type, because, that is probably were it's gonna be used.
            setattr(sys.modules[__name__], '%s.%s_py'%(targetmodule.__name__, name), kpy )
            #setattr(sys.modules[__name__], '%s_py'%(name), kpy )
            setattr(targetmodule, '%s_py'%(name), kpy )
            _created+=1
            if klass.__module__ != targetmodule.__name__: # copy also to generated
                setattr(sys.modules[klass.__module__], '%s_py'%(name), kpy )
                #log.debug("Created %s_py"%klass)
    log.debug('created %d POPO types in %s'%( _created, targetmodule.__name__))
    return

def registerModule( targetmodule ):
    ''' 
    Registers a ctypes module. To be run by target module.
    
    All members in this module will be registered, against their pointer types,
    in a lookup table.
    
    Creates POPO's to be able to unpickle ctypes.
    '''
    log.info('registering module %s'%(targetmodule))
    if targetmodule in registeredModules():
        log.warning('Module %s already registered. Skipping.'%(targetmodule))
        return
    _registered = 0
    for name,klass in inspect.getmembers(targetmodule, inspect.isclass):
        if klass.__module__.startswith(targetmodule.__name__) and (
                issubclass(klass, ctypes.Structure) or issubclass(klass, ctypes.Union)) :
            _registered += 1
    if _registered == 0:
        log.warning('No class found. Maybe you need to model.copyGeneratedClasses ?')
    # create POPO's
    createPOPOClasses( targetmodule )
    __book.addModule(targetmodule)
    log.debug('registered %d types'%( _registered))
    log.debug('registered %d module total'%(len(__book.getModules())))
    return

def isRegistered(cls):
    #return cls in sys.modules[__name__].__dict__.values()
    return __book.isRegisteredType(cls)

#### FIXME DELETE register(LoadableMembersStructure)


if not hasattr(ctypes,'proxy'): # its not a proxy
    global ctypes
    # we need to switch to a ctypes proxy (CString, LoadableMembers...)
    from haystack import types
    ctypes = types.load_ctypes_default()


