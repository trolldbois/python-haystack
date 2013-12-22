

def reload_ctypes(longsize, pointersize, longdoublesize):
    """Imports a proxy to ctypes modules tunes to return types adapted to a 
    target architecture"""
    instance = CTypesProxy(longsize, pointersize, longdoublesize)
    return instance

def set_ctypes_module(ctypesproxy):
    """Change the global ctypes module to a specific proxy instance"""
    if not isinstance(ctypesproxy, CTypesProxy):
        raise TypeError('CTypesProxy instance expected.')
    import sys
    sys.modules['ctypes'] = ctypesproxy
    return

class CTypesProxy(object):
    """# TODO: set types in config.Types
    # ctypeslib generate python code based on config.Types.*
    # never import ctypes, but proxy always through instance of config.
    # flow:
    # a) init config with size/etc.
    # b) init model instance with config instance
    # c) create structure & Union proxied in model instance
    # d) refer to config through dynamically generated Structure/Union classes.

    # sys.modules['ctypes'] = proxymodule/instance

    By default do not load this in model
    """
    def __init__(longsize, pointersize, longdoublesize):
        """Proxies 'the real' ctypes."""
        self.__proxy = True
        self.__longsize = longsize
        self.__pointersize = pointersize
        self.__longdoublesize = longdoublesize
        # remove all refs to the ctypes modules
        import sys
        if hasattr(sys.modules, 'ctypes'):
            del sys.modules['ctypes']
        # import the real one
        import ctypes
        self.__real_ctypes = ctypes
        # copy every members
        for name in dir(ctypes):
            setattr(self, name, getattr(ctypes, name))
        del ctypes
        # replace it.
        sys.modules['ctypes'] = self
        self.__init_types()
        pass        

    def __init_types(self):
        self.__set_void()
        self.__set_int128()
        self.__set_long()
        self.__set_float()
        self.__set_pointer()
        return

    def __set_void(self):
        self.void = None
        return
        
    def __set_int128(self):
        self.c_int128 = self.__real_ctypes.c_ubyte*16
        self.c_uint128 = self.c_int128
        return

    def __set_long(self):
        # use host type if target is the same
        if self.sizeof(self.__real_ctypes.c_long) == self.__longsize:
            return
        if self.__longsize == 4:
            self.c_long = self.__real_ctypes.c_int32
            self.c_ulong = self.__real_ctypes.c_uint32
        elif self.__longsize == 8:
            self.c_long = self.__real_ctypes.c_int64
            self.c_ulong = self.__real_ctypes.c_uint64
        else:
            raise NotImplementedError('long size of %d is not handled'%(self.__longsize))

    def __set_float(self):
        # use host type if target is the same
        if self.sizeof(self.__real_ctypes.c_longdouble) == self.__longdoublesize:
            return
        self.c_longdouble = self.c_ubyte*self.__longdoublesize
        return

    def __set_pointer(self):
        # TODO: c_char_p ?
        # if host pointersize is same as target, keep ctypes pointer function.
        if self.sizeof(self.__real_ctypes.c_void_p) == self.__pointersize:
            return
        # get the replacement type.
        if self.__pointersize == 4:
            replacement_type = self.__real_ctypes.c_uint32
            replacement_type_char = self.__real_ctypes.c_uint32._type_
        elif self.__pointersize == 8:
            replacement_type = self.__real_ctypes.c_uint64
            replacement_type_char = self.__real_ctypes.c_uint64._type_
        else:
            raise NotImplementedError('pointer size of %d is not handled'%(self.__pointersize))
        POINTERSIZE = self.__pointersize
        # required to access _ctypes
        import _ctypes
        # Emulate a pointer class using the approriate c_int32/c_int64 type
        # The new class should have :
        # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
        def POINTER_T(pointee):
            # a pointer should have the same length as LONG
            fake_ptr_base_type = replacement_type
            # specific case for c_void_p
            if pointee is None: # VOID pointer type. c_void_p.
                pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
                clsname = 'c_void'
            else:
                clsname = pointee.__name__
            # make template
            class _T(_ctypes._SimpleCData,):
                _type_ = replacement_type_char
                _subtype_ = pointee
                def _sub_addr_(self):
                    return self.value
                def __repr__(self):
                    return '%s(%d)'%(clsname, self.value)
                def contents(self):
                    raise TypeError('This is not a ctypes pointer.')
                def __init__(self, **args):
                    raise TypeError('This is not a ctypes pointer. It is not instanciable.')
            _class = type('LP_%d_%s'%(POINTERSIZE, clsname), (_T,),{}) 
            return _class
        self.POINTER = POINTER_T
        return

    #import sys
    #from inspect import getmembers, isclass
    #self = sys.modules[__name__]
    def _p_type(s):
        """CHECKME: Something about self reference in structure fields in ctypeslib"""
        return dict(getmembers(self, isclass))[s]
