#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import dump_loader
from haystack import utils
from haystack.outputters import text
from haystack.outputters import python


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

from test.haystack import SrcTests

class TestLoadMembers(SrcTests):
    """Basic types"""
    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
    
    def tearDown(self):
        from haystack import model
        model.reset()
        self.mappings = None
        pass
    
    def test_basic_types(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['struct_a'][0]
        m = self.mappings.getMmapForAddr(offset)
        a = m.readStruct(offset, ctypes5_gen32.struct_a)
        ret = a.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        import ctypes
        self.assertEquals(int(self.sizes['struct_a']), ctypes.sizeof(a))

        self.assertEquals(int(self.values['struct_a.a']), a.a)
        self.assertEquals(int(self.values['struct_a.b']), a.b)
        self.assertEquals(int(self.values['struct_a.c']), a.c)
        self.assertEquals(int(self.values['struct_a.d']), a.d)
        self.assertEquals(int(self.values['struct_a.e']), a.e)
        self.assertEquals(float(self.values['struct_a.f']), a.f)
        self.assertEquals(float(self.values['struct_a.g']), a.g)
        self.assertEquals(float(self.values['struct_a.h']), a.h)


        offset = self.offsets['union_au'][0]
        m = self.mappings.getMmapForAddr(offset)
        au = m.readStruct(offset, ctypes5_gen32.union_au)
        ret = au.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        self.assertEquals(int(self.sizes['union_au']), ctypes.sizeof(au))
        self.assertEquals(int(self.values['union_au.d']), au.d)
        self.assertEquals(float(self.values['union_au.g']), au.g)
        self.assertEquals(float(self.values['union_au.h']), au.h)
        
        return 

    def test_basic_signed_types(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['union_b'][0]
        m = self.mappings.getMmapForAddr(offset)
        b = m.readStruct(offset, ctypes5_gen32.union_b)
        ret = b.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        import ctypes
        self.assertEquals(int(self.sizes['union_b']), ctypes.sizeof(b))
        self.assertEquals(int(self.values['union_b.a']), b.a)
        self.assertEquals(int(self.values['union_b.b']), b.b)
        self.assertEquals(int(self.values['union_b.c']), b.c)
        self.assertEquals(int(self.values['union_b.d']), b.d)
        self.assertEquals(int(self.values['union_b.e']), b.e)
        # char 251
        self.assertEquals((self.values['union_b.g']), b.g)
        
        return 

    def test_bitfield(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['struct_c'][0]
        m = self.mappings.getMmapForAddr(offset)
        c = m.readStruct(offset, ctypes5_gen32.struct_c)
        ret = c.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)

        import ctypes
        self.assertEquals(int(self.sizes['struct_c']), ctypes.sizeof(c))

        self.assertEquals(int(self.values['struct_c.a1']), c.a1)
        self.assertEquals(int(self.values['struct_c.b1']), c.b1)
        self.assertEquals(int(self.values['struct_c.c1']), c.c1)
        self.assertEquals(int(self.values['struct_c.d1']), c.d1)
        self.assertEquals(str(self.values['struct_c.a2']), c.a2)
        self.assertEquals(int(self.values['struct_c.b2']), c.b2)
        self.assertEquals(int(self.values['struct_c.c2']), c.c2)
        self.assertEquals(int(self.values['struct_c.d2']), c.d2)
        self.assertEquals(int(self.values['struct_c.h']), c.h)
        
        return 

    def test_complex(self):
        from test.src import ctypes5_gen32        
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.mappings.getMmapForAddr(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)

        import ctypes
        self.assertEquals(int(self.sizes['struct_d']), ctypes.sizeof(d))
        # other tests are too complex to be done in ctypes.
        # that is why d.toPyObject() exists.

class TestRealSSH(unittest.TestCase):
    """Basic types"""
    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/dumps/ssh/ssh.1/')
        self.classname = 'sslsnoop.ctypes_openssh.session_state'
        self.known_offset = 0xb84ee318
    
    def tearDown(self):
        from haystack import model
        model.reset()
        self.mappings = None
        pass
    
    def test_real_life(self):
        from sslsnoop import ctypes_openssh
        from sslsnoop import ctypes_openssl
        m = self.mappings.getMmapForAddr(self.known_offset)
        ss = m.readStruct(self.known_offset, ctypes_openssh.session_state)
        ret = ss.loadMembers(self.mappings, 10 )
        self.assertTrue(ret)
        
        import ctypes

        self.assertEquals(ss.connection_in, 3)
        self.assertEquals(ss.connection_out, 3)
        
        # receive
        r_app_data = ss.receive_context.getEvpAppData(self.mappings)
        ctx,rounds = r_app_data.getCtx()
        self.assertEquals(ctx,'''o\x1a\x86\xb9\x9b\xb3\xb9\x1b!\x8a\xb1\x0e\x87E\x16E\x01\r\xe8\xff\x9a\xbeQ\xe4\xbb4\xe0\xea<q\xf6\xafx\xe6K\xbf\xe2X\x1a[Yl\xfa\xb1e\x1d\x0c\x1e\n\xab\xefE\xe8\xf3\xf5\x1e\xb1\x9f\x0f\xaf\xd4\x82\x03\xb1\xc2\xe3\xfc6*\x10\t(\x9b\x8f\x06\x87O\r\x056\xc7g+M\xedw"ev\xf8$\xe29\xf5!\xd4\x8fu\xcd\x90b\x02\xef\xf5\x14\xfa\xcb\x17-\x0f\xea\xc3\xa1\xad\xbbW\xc3\xafT\xa2\xd7U\x9f\xb5\xfaZuv\x99\x80\x05JZ/Q\xe8\x8dz\xce]w \xbb+hu\xb2\xbb2Z\xe3S\xbf -\x0e\xc8\x00\x96%W\x9d\xd1\x1de\xc72N\xda\xe7\x1f@\x12\xe7\x89e\xe1\xf3\x06\x1a/E\\t\x8d\xa7\xc2\xde\xfb\x198Xi{\x8e\xa2\xb7\xcd\xe4\xfc\x15/Jf\x83\xa1\xc0\xe0\xf1\x03\x16*?Ul\x84\x9d\xb7\xd2\xee\x0b)Hhy\x8b\x9e\xb2\xc7\xdd\xf4\x0c%?Zv\x93\xb1\xd0\xf0''')
        
        self.assertEquals(rounds,10)
        receive_cipher_ssl = self.mappings.getRef(ctypes_openssl.EVP_CIPHER,
                                utils.get_pointee_address(ss.receive_context.evp.cipher))
        receive_cipher_ssh = ss.receive_context.getCipher(self.mappings)
        self.assertEquals(receive_cipher_ssl.block_size, 16)
        self.assertEquals(receive_cipher_ssl.key_len, 16)
        self.assertEquals(receive_cipher_ssl.iv_len, 16)
        self.assertEquals(ss.receive_context.evp.key_len, 16)
        self.assertEquals(receive_cipher_ssh.getName(self.mappings), 'aes128-ctr')
        self.assertEquals(receive_cipher_ssh.block_size, 16)
        self.assertEquals(receive_cipher_ssh.key_len, 16)

        # send
        s_app_data = ss.send_context.getEvpAppData(self.mappings)
        ctx,rounds = s_app_data.getCtx()
        self.assertEquals(ctx,'''\x11\x07Xvm\xaa!\x9a\x185\x18\xe7\x07S\x84\xdb\xa8\xc2\xb5(\xc5h\x94\xb2\xdd]\x8cU\xda\x0e\x08\x8e\xb1\x95\x1e\x1at\xfd\x8a\xa8\xa9\xa0\x06\xfds\xae\x0es>\x1a\xfa\xb5J\xe7p\x1d\xe3Gv\xe0\x90\xe9x\x93\xe2z\xe4\x01\xa8\x9d\x94\x1cK\xda\xe2\xfc\xdb3\x9aoJ\xc3'\xa9\xe2^\xb3\xb5\xa9\x84QIr\xb7\xcb&\xbd\x83\x8e\x96_\xdd=#\xf6Ylj\x84\xee\xa7L\x94\xdc\xa6\x8a\xcb\x01\x9b\xa9=X\xf7\xc3\xb9\xb6P\x8f\xe7\x8a\xe8Y,\x8bs\xf0\x11\xd3\x843\xa8e\xd4\xbc\x82H\xa5\n\xae\xc3\xd6\xfa\xbf\x10R\xc9\x17u\x86u\x1f\xb88x\xb1{\xee\x82\x0ek\xbcK\x19\x1e:>\xb2\xcc\xe7\x03 >]}\x8e\xa0\xb3\xc7\xdc\xf2\t!:To\x8b\xa8\xc6\xe5\x05\x16(;Odz\x91\xa9\xc2\xdc\xf7\x130Nm\x8d\x9e\xb0\xc3\xd7\xec\x02\x191Jd\x7f\x9b\xb8\xd6\xf5\x15&8K_t\x8a\xa1\xb9''')
        
        self.assertEquals(rounds,10)
        send_cipher_ssl = self.mappings.getRef(ctypes_openssl.EVP_CIPHER,
                                utils.get_pointee_address(ss.send_context.evp.cipher))
        send_cipher_ssh = ss.send_context.getCipher(self.mappings)
        self.assertEquals(send_cipher_ssl.block_size, 16)
        self.assertEquals(send_cipher_ssl.key_len, 16)
        self.assertEquals(send_cipher_ssl.iv_len, 16)
        self.assertEquals(ss.send_context.evp.key_len, 16)
        self.assertEquals(send_cipher_ssh.getName(self.mappings), 'aes128-ctr')
        self.assertEquals(send_cipher_ssh.block_size, 16)
        self.assertEquals(send_cipher_ssh.key_len, 16)

        import code
        code.interact(local=locals())
      
        return 





if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)

