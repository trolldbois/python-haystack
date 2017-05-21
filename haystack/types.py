# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

from past.builtins import long
import ctypes
import logging
import sys

log = logging.getLogger('types')

# let's use a cache
__PROXIES = {}


def load_ctypes_default():
    """Load a wrapper around the ctypes local platform."""
    # get the hosts' types
    longsize = ctypes.sizeof(ctypes.c_long)
    pointersize = ctypes.sizeof(ctypes.c_void_p)
    longdoublesize = ctypes.sizeof(ctypes.c_longdouble)
    return build_ctypes_proxy(longsize, pointersize, longdoublesize)


def build_ctypes_proxy(longsize, pointersize, longdoublesize):
    """Make a ctypes proxy with these charateristics."""
    if (longsize, pointersize, longdoublesize) in __PROXIES:
        instance = __PROXIES[(longsize, pointersize, longdoublesize)]
        return instance
    instance = CTypesProxy(longsize, pointersize, longdoublesize)
    __PROXIES[(longsize, pointersize, longdoublesize)] = instance
    return instance


def is_ctypes_instance(obj):
    """Checks if an object is a ctypes type object"""
    return issubclass(type(obj), ctypes.Structure) or issubclass(type(obj), ctypes.Union)


def check_arg_is_type(func):
    def check_arg(self, objtype):
        if not isinstance(objtype, type):
            return False
        return func(self, objtype)
    check_arg.__name__ = func.__name__
    check_arg.__doc__ = func.__doc__
    check_arg.__dict__.update(func.__dict__)
    return check_arg


class CTypesProxy(object):

    """# TODO: set types in _target_platform.Types
    # ctypeslib generate python code based on _target_platform.Types.*
    # never import ctypes, but proxy always through instance of _target_platform.
    # flow:
    # a) init _target_platform with size/etc.
    # b) init model instance with _target_platform instance
    # c) create structure & Union proxied in model instance
    # d) refer to _target_platform through dynamically generated Structure/Union classes.

    # sys.modules['ctypes'] = proxymodule/instance

    By default do not load this in model
    """

    def __init__(self, longsize, pointersize, longdoublesize):
        """Proxies 'the real' ctypes."""
        self.proxy = True
        self.__longsize = longsize
        self.__pointersize = pointersize
        self.__longdoublesize = longdoublesize
        self.__real_ctypes = ctypes
        # TODO delete
        if hasattr(ctypes, 'proxy'):
            raise RuntimeError('base ctype should not be a proxy')
        # copy every members from ctypes to our proxy instance
        for name in dir(ctypes):
            if name == '_pointer_type_cache':
                setattr(self, name, dict())
            elif not name.startswith('__'):
                setattr(self, name, getattr(ctypes, name))
                # print name
        self.__init_types()
        self.__name__ = "CTypesProxy-%d:%d:%d" % (self.__longsize,
                                                  self.__pointersize,
                                                  self.__longdoublesize)
        log.debug("types: %s %s",str(self.c_void_p),id(self.c_void_p))
        pass

    def __init_types(self):
        self.__set_void()
        self.__set_int128()
        self.__set_long()
        self.__set_float()
        self.__set_pointer()
        # change function types
        self.__set_CFUNCTYPE()
        self.__set_records()
        self.__set_utils_types()
        return

    def __set_void(self):
        self.void = None
        return

    def __set_int128(self):
        self.c_int128 = self.__real_ctypes.c_ubyte * 16
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
            raise NotImplementedError('long size of %d is not handled' % self.__longsize)

    def __set_float(self):
        SIZE = self.__longdoublesize
        HOSTSIZE = self.sizeof(self.__real_ctypes.c_longdouble)
        HOSTDOUBLESIZE = self.sizeof(self.__real_ctypes.c_double)
        # use host type if target is the same
        if SIZE == HOSTSIZE:
            return
        # does not work
        # if SIZE == HOSTDOUBLESIZE:
        #    self.c_longdouble = self.__real_ctypes.c_double
        #    return

        class c_longdouble(self.__real_ctypes.Union):
            """
            This is our own implementation of a longdouble.
            It could be anywhere from 64(win) to 80 bits, stored as 8, 12,
            or 16 bytes.
            """
            _pack_ = True
            _fields_ = [("physical", self.c_ubyte * SIZE)]
            _type_ = 'g'  # fake it
            # we can cast 8 bytes long double in 16 bytes long double
            if HOSTSIZE > SIZE:
                def __eq__(thisself, other):
                    v = self.get_real_ctypes_member('c_longdouble').from_address(self.addressof(thisself)).value
                    return v == other

                def __repr__(thisself):
                    return repr(self.get_real_ctypes_member('c_longdouble').from_address(self.addressof(thisself)))

                @property
                def value(thisself):
                    return self.get_real_ctypes_member('c_longdouble').from_address(self.addressof(thisself)).value
            else:
                # good luck with that.
                def __eq__(thisself, other):
                    other2 = (self.c_ubyte *SIZE).from_address(self.addressof(other))
                    for i in range(SIZE):
                        if thisself[i] != other2[i]:
                            return False
                    return True

                def __repr__(thisself):
                    return 'c_longdouble(fake)'

                @property
                def value(thisself):
                    return float(0.0)  # FIXME
                #
        self.c_longdouble = c_longdouble
        return

    def __set_pointer(self):
        # TODO: c_char_p ?
        # if host pointersize is same as target, keep ctypes pointer function.
        if self.sizeof(self.__real_ctypes.c_void_p) == self.__pointersize:
            # use the same pointer cache
            self._pointer_type_cache = self.__real_ctypes._pointer_type_cache
            # see __init__
            # pylint: disable=access-member-before-definition
            self.__ptrt = self.POINTER(self.c_byte).__bases__[0]
            return
        # get the replacement type.
        if self.__pointersize == 4:
            replacement_type = self.__real_ctypes.c_uint32
            replacement_type_char = self.__real_ctypes.c_uint32._type_
        elif self.__pointersize == 8:
            replacement_type = self.__real_ctypes.c_uint64
            replacement_type_char = self.__real_ctypes.c_uint64._type_
        else:
            raise NotImplementedError('pointer size of %d is not handled' % self.__pointersize)
        POINTERSIZE = self.__pointersize
        # required to access _ctypes
        import _ctypes
        # Emulate a pointer class using the approriate c_int32/c_int64 type
        # The new class should have :
        # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
        my_ctypes = self
        # special class for c_void_p

        class _T_Simple(_ctypes._SimpleCData,):
            _type_ = replacement_type_char

            @property
            def _sub_addr_(myself):
                return myself.value

            def __init__(myself, value):
                myself.value = value

            def __repr__(myself):
                return '%s(%d)' % (type(myself).__name__, myself.value)
        self._T_Simple = _T_Simple

        def POINTER_T(pointee):
            if pointee in my_ctypes._pointer_type_cache:
                return my_ctypes._pointer_type_cache[pointee]
            # specific case for c_void_p
            subtype = pointee
            if pointee is None:  # VOID pointer type. c_void_p.
                clsname = 'LP_%d_c_void_p' % POINTERSIZE
                _class = type(clsname, (_T_Simple,), {})
                _class._subtype_ = type(None)
                my_ctypes._pointer_type_cache[pointee] = _class
                # additionnaly register this type in this module fo pickling
                setattr(sys.modules[__name__], clsname, _class)
                return _class

            clsname = pointee.__name__
            # template that creates a PointerType to pointee (clsname *)
            # we have to fake the size of the structure to
            # replacement_type_char's size.
            # so we replace _type_ with the fake type of the expected size.
            # and we had _subtype_ that will be queried by our helper
            # functions.

            class _T(_T_Simple,):
                _subtype_ = subtype  # could use _pointer_type_cache

                def __repr__(myself):
                    return '%s(%d)' % (type(myself).__name__, myself.value)

                @property
                def contents(myself):
                    return myself._subtype_.from_address(myself.value)
                    # raise TypeError('This is not a ctypes pointer.')

                def __init__(myself, _value=None):
                    if _value is None:
                        myself.value = 0
                        return
                    if not isinstance(_value, subtype):
                        raise TypeError('%s expected, not %s' % (subtype, type(_value)))
                    myself.value = my_ctypes.addressof(_value)
                    # raise TypeError('This is not a ctypes pointer.')

            _class = type('LP_%d_%s' % (POINTERSIZE, clsname), (_T,), {})
            my_ctypes._pointer_type_cache[pointee] = _class
            # additionally register this type in this module fo pickling
            setattr(sys.modules[__name__], clsname, _class)
            return _class
        # end of POINTER_T
        self.POINTER = POINTER_T
        self.__ptrt = self._T_Simple
        self._pointer_type_cache.clear()
        self.c_void_p = self.POINTER(None)
        # c_void_p is a simple type
        # self.c_void_p = type('c_void_p', (_T_Simple,),{})
        # other are different
        self.c_char_p = self.POINTER(self.c_char)
        self.c_wchar_p = self.POINTER(self.c_wchar)

        setattr(sys.modules[__name__], 'c_void_p', self.c_void_p)
        setattr(sys.modules[__name__], 'c_char_p', self.c_char_p)
        setattr(sys.modules[__name__], 'c_wchar_p', self.c_wchar_p)

        # set the casting function
        self.cast = self.__cast
        return

    def __set_records(self):
        """
        DO NOT DO :Replaces ctypes.Structure and ctypes.Union with their CTypesRecordConstraintValidator

        counterparts. Add a CString type.
        MAYBE FIXME: These root types will only be valid when the ctypes record is
        used with the adequate CTypesProxy.
        """
        class CString(self.__real_ctypes.Union):
            """
            This is our own implementation of a string for ctypes.
            ctypes.c_char_p can not be used for memory parsing, as it tries to load
            the string itself without checking for pointer validation.

            it's basically a Union of a string and a pointer.
            """
            _fields_ = [
                ("string", self.c_char_p),
                ("ptr", self.POINTER(self.c_ubyte))
            ]
            _type_ = 's'  # fake it

            def read_string(self, memoryMap, address, max_size, chunk_length=256):
                """ Read character up to max_size until a \x00 byte is found """
                string = []
                size = 0
                truncated = False
                while True:
                    done = False
                    data = memoryMap.read_bytes(address, chunk_length)
                    if '\0' in data:
                        done = True
                        data = data[:data.index('\0')]
                    if max_size <= size + chunk_length:
                        data = data[:(max_size - size)]
                        string.append(data)
                        truncated = True
                        break
                    string.append(data)
                    if done:
                        break
                    size += chunk_length
                    address += chunk_length
                return ''.join(string), truncated
        # and there we have it. We can load basicmodel
        self.CString = CString

        class CWString(self.__real_ctypes.Union):
            """
            This is our own implementation of a wide char string for ctypes.
            ctypes.c_char_p can not be used for memory parsing, as it tries to load
            the string itself without checking for pointer validation.

            it's basically a Union of a string and a pointer.
            """
            _fields_ = [
                ("string", self.c_wchar_p),
                ("ptr", self.POINTER(self.c_ubyte))
            ]
            _type_ = 's'  # fake it

            def read_string(self, memoryMap, address, max_size, chunk_length=256):
                """ Read character up to max_size until a \x00\x00 byte is found """
                string = []
                size = 0
                truncated = False
                while True:
                    done = False
                    data = memoryMap.read_bytes(address, chunk_length)
                    if '\0\0' in data:
                        done = True
                        data = data[:data.index('\0\0')]
                    if max_size <= size + chunk_length:
                        data = data[:(max_size - size)]
                        string.append(data)
                        truncated = True
                        break
                    string.append(data)
                    if done:
                        break
                    size += chunk_length
                    address += chunk_length
                return ''.join(string), truncated
        # and there we have it. We can load basicmodel
        self.CWString = CWString

        return

    def __set_utils_types(self):
        """Creates some types to compare to"""
        self.__arrayt = type(self.c_byte * 1)
        # self.__cfuncptrt = type(type(self.memmove))
        # class _p(self.Structure):
        #    pass
        # self.__ptrt = type(self.POINTER(_p))
        self.__basic_types_name = {
            'c_bool': '?',
            'c_char': 'c',
            'c_byte': 'b',
            'c_ubyte': 'B',
            'c_short': 'h',
            'c_ushort': 'H',
            'c_int': 'i',  # c_int is c_long
            'c_uint': 'I',
            'int': 'i',
            'c_longlong': 'q',
            'c_ulonglong': 'Q',
            'c_float': 'f',
            'c_double': 'd',
            'c_longdouble': 'g',
            'c_char_p': 's',
            'c_void_p': 'P',
            # 'c_void': 'P', ## void in array is void_p ##DEBUG
        }
        if self.__longsize == 4:
            # long == int
            self.__basic_types_name.update({'c_long': 'i',
                                            'c_ulong': 'I',
                                            'long': 'i',
                                            'c_void': 'I'})
        elif self.__longsize == 8:
            # long == longlong
            self.__basic_types_name.update({'c_long': 'q',
                                            'c_ulong': 'Q',
                                            'long': 'q',
                                            'c_void': 'Q'})
        # we need to account for the possible changes in c_longdouble
        self.__basic_types = set([getattr(self, k) for k in self.__basic_types_name.keys() if hasattr(self, k)])
        return

    def __cast(self, obj, next_type):
        # obj and next_type have to be our instances
        # FIXME: probably buggy
        if not isinstance(obj, self._T_Simple):
            raise TypeError('%s is not a haystack ctypes pointer' % type(obj))
        if not issubclass(next_type, self._T_Simple):
            raise TypeError('%s is not a haystack ctypes pointer' % next_type)
        instance = next_type()
        instance.value = obj.value
        return instance

    def __set_CFUNCTYPE(self):
        if self.sizeof(self.__real_ctypes.c_void_p) == self.__pointersize:
            # see __init__
            # pylint: disable=access-member-before-definition
            self.__cfuncptrt = self.CFUNCTYPE(self.c_uint).__bases__[0]
            return

        class _FUNC_T(self._T_Simple,):

            def __init__(myself, *a, **args):
                pass

        def fn_FUNC_T(*args):
            _class = type('FN_%d_CFunctionType' %(self.__pointersize), (_FUNC_T,), {})
            return _class
        self.CFUNCTYPE = fn_FUNC_T
        self.__cfuncptrt = _FUNC_T
        return

    def _p_type(self):
        """
        Used when ctypeslib produce a record with a pointer reference to the same record
        :return:
        """
        # FIXME: Something about self reference in structure fields from
        # ctypeslib.
        # Check if still used
        import inspect
        return dict(inspect.getmembers(self, inspect.isclass))[self]

    def get_real_ctypes_member(self, typename):
        return getattr(self.__real_ctypes, typename)

    def get_pack_format(self):
        """Return the struct.pack/unpack format translation table"""
        return dict(self.__basic_types_name)

    def get_bytes_for_record_field(self, record, fieldname):
        """Return the bytes behind a specific field of a record"""
        _class = record.__class__
        _cls_field = getattr(_class,fieldname)
        _ofs = getattr(_class, fieldname).offset
        _size = getattr(_class, fieldname).size
        # FIXME, use address + _ofs instead
        _bytes = (self.c_byte*(_ofs+_size)).from_buffer_copy(record)[_ofs:]
        return _bytes

    def is_array_of_basic_instance(self, obj):
        """Checks if an object is a array of basic types.
        It checks the type of the first element.
        The array should not be null :).
        """
        # FIXME: deprecated
        if not hasattr(obj, '_type_'):
            return False
        if self.is_array_type(type(obj)):
            if len(obj) == 0:
                return False  # no len is no BasicType
            if self.is_pointer_type(obj._type_):
                return False
            if self.is_basic_type(obj._type_):
                return True
        return False

    @check_arg_is_type
    def is_array_type(self, objtype):
        """Checks if an object is a ctype array."""
        return isinstance(objtype, self.__arrayt)  # _ctypes.PyCArrayType

    @check_arg_is_type
    def is_array_of_basic_type(self, objtype):
        """Checks if an object is a ctype array of basic types."""
        return self.is_array_type(objtype) and hasattr(objtype, '_type_') and self.is_basic_type(objtype._type_)

    @check_arg_is_type
    def is_basic_type(self, objtype):
        """Checks if an object is a ctypes basic type, or a python basic type."""
        if not hasattr(objtype, '_type_'):
            # could be python types
            return objtype in [int, long, float, bool]
        return self.is_basic_ctype(objtype)

    @check_arg_is_type
    def is_basic_ctype(self, objtype):
        """Checks if an object is a ctypes basic type, or a python basic type."""
        if objtype in [self.c_char_p, self.c_void_p, self.CString]:
            return False
        # DOC: if <ctypes.c_uint> is not in self.__basic_types, its probably
        # because you are using the wrong ctypes Proxy instance
        return objtype in self.__basic_types

    @check_arg_is_type
    def is_cstring_type(self, objtype):
        """Checks if an object is our CString."""
        return issubclass(objtype, self.CString) or issubclass(objtype, self.CWString)

    @check_arg_is_type
    def is_function_type(self, objtype):
        """Checks if an object is a function pointer."""
        # return self.__cfuncptrt == type(objtype)
        return issubclass(objtype, self.__cfuncptrt)
        # return isinstance(objtype, self.__cfuncptrt)

    @check_arg_is_type
    def is_pointer_type(self, objtype):
        """ Checks if an object is a ctypes pointer.m CTypesPointer or CSimpleTypePointer"""
        # if hasattr(objtype, '_subtype_'):
        if issubclass(objtype, self.__ptrt):
            return True
        if hasattr(objtype, '_type_'):
            # all basic types, pointers and array have a _type_
            return not (self.is_basic_type(objtype) or self.is_array_type(objtype))  # kinda true. I guess.
        # remaining case
        return self.is_function_type(objtype)

    @check_arg_is_type
    def get_pointee_type(self, objtype):
        """Returns the pointee type of a pointer type"""
        if not self.is_pointer_type(objtype):
            raise TypeError('not a pointer type')
        if hasattr(objtype, '_subtype_'):  # haystack
            return objtype._subtype_
        elif hasattr(objtype, '_type_'):
            return objtype._type_
        else:
            raise TypeError('subtype has neither _subtype_ nor _type_ fields.')

    @check_arg_is_type
    def is_pointer_to_array_type(self, objtype):
        """Checks if an object is a pointer to a BasicType"""
        if hasattr(objtype, '_subtype_'):  # haystack
            return self.is_array_type(objtype._subtype_)
        return self.is_pointer_type(objtype) and hasattr(objtype, '_type_') and self.is_array_type(objtype._type_)

    @check_arg_is_type
    def is_pointer_to_basic_type(self, objtype):
        """Checks if an object is a pointer to a BasicType"""
        if hasattr(objtype, '_subtype_'):  # haystack
            return self.is_basic_type(objtype._subtype_)
        return self.is_pointer_type(objtype) and hasattr(objtype, '_type_') and self.is_basic_type(objtype._type_)

    @check_arg_is_type
    def is_pointer_to_struct_type(self, objtype):
        """Checks if an object is a pointer to a Structure"""
        if hasattr(objtype, '_subtype_'):
            return self.is_struct_type(objtype._subtype_)
        return self.is_pointer_type(objtype) and hasattr(objtype, '_type_') and self.is_struct_type(objtype._type_)

    @check_arg_is_type
    def is_pointer_to_union_type(self, objtype):
        """Checks if an object is a pointer to a Union"""
        if hasattr(objtype, '_subtype_'):
            return self.is_union_type(objtype._subtype_)
        return self.is_pointer_type(objtype) and hasattr(objtype, '_type_') and self.is_union_type(objtype._type_)

    @check_arg_is_type
    def is_pointer_to_void_type(self, objtype):
        """FIXME Checks if an object is a ctypes pointer.m CTypesPointer or CSimpleTypePointer"""
        # FIXME: DOCME what is that _subtype_ case
        if hasattr(objtype, '_subtype_'):
            if isinstance(None, objtype._subtype_):
                return True
        # FIXME: DOCME what are these cases ? not auto-loading ?
        # self.POINTER(None) is required, because sometimes, c_void_p !=
        # c_void_p :)
        return objtype in [self.c_char_p, self.c_wchar_p, self.c_void_p, self.POINTER(None)]

    @check_arg_is_type
    def is_struct_type(self, objtype):
        """ Checks if an object is a ctypes Structure."""
        return issubclass(objtype, self.get_real_ctypes_member('Structure'))

    @check_arg_is_type
    def is_union_type(self, objtype):
        """ Checks if an object is a ctypes Union."""
        # force ignore the longdouble construct
        if objtype == self.c_longdouble:
            return False
        # force ignore the CString construct
        #if objtype == self.CString:
        if self.is_cstring_type(objtype):
            return False
        return issubclass(objtype, self.get_real_ctypes_member('Union'))

    def __str__(self):
        return "<haystack.types.CTypesProxy-%d:%d:%d-%x>" % (
            self.__longsize, self.__pointersize, self.__longdoublesize, id(self))

    # TODO implement haystack.utils.bytestr_fmt here

