#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.types."""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

# init ctypes with a controlled type size
from haystack import model
from haystack import types

import operator
import os
import logging
import struct
import unittest

def make_types():
    import ctypes    
    # make some structures.
    class St(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_int) ]
    class St2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_long) ]
    class SubSt2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_longlong) ]
    class Union(ctypes.Union):
      _fields_ = [ ('l',ctypes.c_longlong), ('f',ctypes.c_float)]
    #
    btype = ctypes.c_int
    longt = ctypes.c_long
    voidp = ctypes.c_void_p
    stp = ctypes.POINTER(St)
    stpvoid = ctypes.POINTER(None)
    arra1 = (ctypes.c_long *4)
    arra2 = (St *4)
    arra3 = (ctypes.POINTER(St) *4)
    charp = ctypes.c_char_p
    string = ctypes.CString
    fptr = type(ctypes.memmove)
    arra4 = (fptr*256)
    double = ctypes.c_longdouble
    arra5 = ctypes.c_ubyte*8
    arra6 = ctypes.c_char*32
    ptrUnion = ctypes.POINTER(Union)
    return locals()


class TestReload(unittest.TestCase):
    """Tests sizes after ctypes changes."""

    def setUp(self):
        model.reset()

    # test ctypes._pointer_type_cache
    def test_pointer_type_cache(self):
        """test the comportment of _pointer_type_cache"""
        # between reset(), we keep the reference to the ctypes modules
        # and we don't the pointer cache, that we only share with the default
        # ctypes proxy instance
        ctypes = types.reset_ctypes()
        class X(ctypes.Structure):
            pass

        self.assertNotIn(X, ctypes._pointer_type_cache.keys())
        ctypes.POINTER(X)
        self.assertIn(X, ctypes._pointer_type_cache.keys())

        ctypes = types.reset_ctypes()
        # we keep the cache
        self.assertIn(X, ctypes._pointer_type_cache.keys())

        c4 = types.reload_ctypes(4,4,8)
        c8 = types.reload_ctypes(8,8,16)
        cd = types.load_ctypes_default()
        if c4 != cd:
            newarch = c4
        elif c8 != cd:
            newarch = c4

        # cd and ctypes share a cache
        self.assertIn(X, cd._pointer_type_cache.keys())
        # and cd.POINTER is actually ctypes.POINTER
        self.assertEquals(cd.POINTER, ctypes.POINTER)
        self.assertEquals(cd._pointer_type_cache, ctypes._pointer_type_cache)

        # but not other proxies
        self.assertNotIn(X, newarch._pointer_type_cache.keys())

        class Y(newarch.Structure):
            pass
        self.assertNotIn(Y, cd._pointer_type_cache.keys())
        self.assertNotIn(Y, ctypes._pointer_type_cache.keys())
        self.assertNotIn(Y, newarch._pointer_type_cache.keys())
        newarch.POINTER(Y)
        self.assertNotIn(Y, cd._pointer_type_cache.keys())
        self.assertNotIn(Y, ctypes._pointer_type_cache.keys())
        self.assertIn(Y, newarch._pointer_type_cache.keys())



        pass

    def test_reset_ctypes(self):
        """Test if reset gives the original types"""
        import ctypes
        ctypes = types.reload_ctypes(4,4,8)
        proxy = ctypes
        for name,value in make_types().items():
            globals()[name] = value
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        
        ctypes = types.reset_ctypes()
        # no CString.
        self.assertRaises(AttributeError, make_types)
        self.assertIn('ctypes','%s'%(ctypes) )
        self.assertFalse( hasattr(ctypes,'proxy') )
        return 

    def test_load_ctypes_default(self):
        """Test if the default proxy works"""
        import ctypes
        ctypes = types.reload_ctypes(4,4,8)
        self.assertTrue(ctypes.proxy)
        # test
        ctypes = types.load_ctypes_default()
        self.assertTrue(ctypes.proxy)
        for name,value in make_types().items():
            globals()[name] = value
        # default ctypes should be similar to host ctypes.
        self.assertEquals( ctypes.sizeof(arra1), 4*ctypes.sizeof(ctypes.get_real_ctypes_member('c_long')) )
        self.assertEquals( ctypes.sizeof(stp), ctypes.sizeof(ctypes.get_real_ctypes_member('c_void_p')) )
        self.assertEquals( ctypes.sizeof(arra1), 4*ctypes.sizeof(ctypes.c_long) )
        self.assertEquals( ctypes.sizeof(stp), ctypes.sizeof(ctypes.c_void_p) )
        return 

    def test_reload_ctypes(self):
        """Tests loading of specific arch ctypes."""
        import ctypes
        ctypes = types.reload_ctypes(4,4,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(4,8,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(8,4,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(8,4,16)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 16 )

        # other arch        
        self.assertRaises(NotImplementedError, types.reload_ctypes, 16,8,16) 
        return 

    def test_set_ctypes(self):
        """Test reloading of previous defined arch-ctypes."""
        import ctypes
        x32 = types.reload_ctypes(4,4,8)
        x64 = types.reload_ctypes(8,8,16)
        win = types.reload_ctypes(8,8,8)
        ctypes = types.reset_ctypes()
        
        ctypes = types.set_ctypes(x32)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x32 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        ctypes = types.set_ctypes(x64)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x64 )
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 16 )

        ctypes = types.set_ctypes(win)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, win )
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        ctypes = types.set_ctypes(x32)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x32 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        return 

class TestBasicFunctions(unittest.TestCase):
    """Tests basic haystack.types functions on base types."""

    def setUp(self):
        model.reset()
        import ctypes
        ctypes = types.load_ctypes_default()
        for name,value in make_types().items():
            globals()[name] = value
        self.tests = [St, St2, SubSt2, btype, longt, voidp, stp, stpvoid, arra1,
                      arra2, arra3, charp, string, fptr, arra4, double, arra5,
                      arra6, Union, ptrUnion]

    def _testMe(self, fn, valids, invalids):
        for var in valids:
            self.assertTrue( fn( var ), var )
        for var in invalids:
            self.assertFalse( fn( var ), var )

    def test_is_basic_type(self):
        self.assertTrue(ctypes.c_uint) # TODO FIXME
        valids = [btype, longt, double]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_basic_type, valids, invalids)
        return 

    def test_is_struct_type(self):
        valids = [St, St2, SubSt2]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_struct_type, valids, invalids)
        return 

    def test_is_union_type(self):
        valids = [Union]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_union_type, valids, invalids)
        return 

    def test_is_pointer_type(self):
        valids = [voidp, stp, stpvoid, fptr, charp, string, ptrUnion]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_pointer_type, valids, invalids)
        return 

    def test_is_pointer_to_struct_type(self):
        valids = [stp]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_pointer_to_struct_type, valids, invalids)
        return 

    def test_is_pointer_to_union_type(self):
        valids = [ptrUnion]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_pointer_to_union_type, valids, invalids)
        return 

    def test_is_pointer_to_void_type(self):
        valids = [voidp, stpvoid, charp]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_pointer_to_void_type, valids, invalids)
        return 

    def test_is_function_type(self):
        valids = [fptr]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_function_type, valids, invalids)
        return 

    def test_is_array_of_basic_instance(self):
        valids = [arra1(), arra5(), arra6()]
        invalids = [ v for v in self.tests if v not in valids]
        # we need instances to be invalid
        invalids.extend([ arra2(), arra3(), arra4(), ] )
        for var in valids:
            self.assertTrue( ctypes.is_array_of_basic_instance( var ), var)
        for var in invalids:
            self.assertFalse( ctypes.is_array_of_basic_instance( var ), var )
        return 

    def test_is_array_of_basic_type(self):
        valids = [arra1, arra5, arra6]
        invalids = [ v for v in self.tests if v not in valids]
        for var in valids:
            self.assertTrue( ctypes.is_array_of_basic_type( var ), var)
        for var in invalids:
            self.assertFalse( ctypes.is_array_of_basic_type( var ), var )
        return 

    def test_is_array_type(self):
        valids = [arra1, arra2, arra3, arra4, arra5, arra6]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_array_type, valids, invalids)
        return 

    def test_is_cstring_type(self):
        valids = [string ]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_cstring_type, valids, invalids)
        return 

    def test_is_ctypes(self):
        valids = [St(), St2(), SubSt2()]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( ctypes.is_ctypes_instance, valids, invalids)
        return 


    def test_import(self):
        #''' Do not replace c_char_p '''
        from haystack import basicmodel
        self.assertEquals( ctypes.c_char_p.__name__ , 'c_char_p', 'c_char_p should not be changed')
        self.assertTrue( issubclass(ctypes.Structure, basicmodel.LoadableMembers) )
        self.assertTrue( issubclass(ctypes.Union, basicmodel.LoadableMembers) )
        self.assertIn( ctypes.CString, ctypes.__dict__.values() )


class TestBasicFunctions32(TestBasicFunctions):
    """Tests basic haystack.utils functions on base types for x32 arch."""
    def setUp(self):
        """Have to reload that at every test. classmethod will not work"""
        # use the host ctypes with modif
        model.reset()
        import ctypes
        ctypes = types.reload_ctypes(4,4,8)
        self.assertTrue(ctypes.proxy)
        for name,value in make_types().items():
            globals()[name] = value
        # reload test list after globals have been changed
        self.tests = [St, St2, SubSt2, btype, longt, voidp, stp, stpvoid, arra1,
                      arra2, arra3, charp, string, fptr, arra4, double, arra5,
                      arra6, Union, ptrUnion]

    def test_sizes(self):
        self.assertEquals( ctypes.sizeof(ctypes.c_long), 4)
        self.assertEquals( ctypes.sizeof(ctypes.c_void_p), 4)
        self.assertEquals( ctypes.sizeof(ctypes.POINTER(ctypes.c_int)), 4)
        self.assertEquals( ctypes.sizeof(ctypes.c_char_p), 4)
        self.assertEquals( ctypes.sizeof(ctypes.c_wchar_p), 4)
        self.assertEquals( ctypes.sizeof(arra1), 4*4)
        self.assertEquals( ctypes.sizeof(double), 8)
        return 

    def test_import(self):
        from haystack import basicmodel
        self.assertTrue( issubclass(ctypes.Structure, basicmodel.LoadableMembers) )
        self.assertTrue( issubclass(ctypes.Union, basicmodel.LoadableMembers) )
        self.assertIn( ctypes.CString, ctypes.__dict__.values() )

class TestBasicFunctionsWin(TestBasicFunctions):
    """Tests basic haystack.utils functions on base types for x64 arch."""
    def setUp(self):
        """Have to reload that at every test. classmethod will not work"""
        # use the host ctypes with modif
        model.reset()
        import ctypes
        ctypes = types.reload_ctypes(8,8,8)
        self.assertTrue(ctypes.proxy)
        for name,value in make_types().items():
            globals()[name] = value
        #
        self.tests = [St, St2, SubSt2, btype, longt, voidp, stp, stpvoid, arra1,
                      arra2, arra3, charp, string, fptr, arra4, double, arra5,
                      arra6, Union, ptrUnion]
        
    def test_sizes(self):
        self.assertEquals( ctypes.sizeof(ctypes.c_long), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_void_p), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_char_p), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_wchar_p), 8)
        self.assertEquals( ctypes.sizeof(arra1), 4*8)
        self.assertEquals( ctypes.sizeof(double), 8)
        return 

    def test_import(self):
        from haystack import basicmodel
        self.assertTrue( issubclass(ctypes.Structure, basicmodel.LoadableMembers) )
        self.assertTrue( issubclass(ctypes.Union, basicmodel.LoadableMembers) )
        self.assertIn( ctypes.CString, ctypes.__dict__.values() )

class TestBasicFunctions64(TestBasicFunctions):
    """Tests basic haystack.utils functions on base types for x64 arch."""
    def setUp(self):
        """Have to reload that at every test. classmethod will not work"""
        # use the host ctypes with modif
        model.reset()
        import ctypes
        ctypes = types.reload_ctypes(8,8,16)
        self.assertTrue(ctypes.proxy)
        for name,value in make_types().items():
            globals()[name] = value
        #
        self.tests = [St, St2, SubSt2, btype, longt, voidp, stp, stpvoid, arra1,
                      arra2, arra3, charp, string, fptr, arra4, double, arra5,
                      arra6, Union, ptrUnion]
        
    def test_sizes(self):
        self.assertEquals( ctypes.sizeof(ctypes.c_long), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_void_p), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_char_p), 8)
        self.assertEquals( ctypes.sizeof(ctypes.c_wchar_p), 8)
        self.assertEquals( ctypes.sizeof(arra1), 4*8)
        self.assertEquals( ctypes.sizeof(double), 16)
        return 

    def test_import(self):
        from haystack import basicmodel
        self.assertTrue( issubclass(ctypes.Structure, basicmodel.LoadableMembers) )
        self.assertTrue( issubclass(ctypes.Union, basicmodel.LoadableMembers) )
        self.assertIn( ctypes.CString, ctypes.__dict__.values() )

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main(verbosity=2)


