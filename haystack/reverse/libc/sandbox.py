
'''
	( 'ptr_ext_lib' , ctypes.c_void_p ), # @ b6b3ef68 /usr/lib/libQtCore.so.4.7.2 


local python
b6c63000-b6efa000 r-xp 00000000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4
b6efa000-b6f01000 r--p 00296000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4
b6f01000-b6f04000 rw-p 0029d000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4

'''
import struct
import os
import sys
import ctypes

offset = 0xb6b3ef68 - 0xb68b1000

from haystack import memory_mapping, utils

class Dummy():
  pass

class Dl_info(ctypes.Structure):
  _fields_ = [
  ('dli_fname', ctypes.c_char_p), #Pathname of shared object that contains address
  ('dli_fbase', ctypes.c_void_p), #Address at which shared object is loaded
  ('dli_sname', ctypes.c_char_p), #Name of nearest symbol with address lower than addr
  ('dli_saddr', ctypes.c_void_p)  #Exact address of symbol named in dli_sname
  ]

def getMappings():
  me = Dummy()
  me.pid = os.getpid()
  return memory_mapping.readProcessMappings(me)

  
def test1():
  info = Dl_info()

  #handle = libdl.dlopen('/usr/lib/libQtCore.so.4.7.2')

  libname = '/usr/lib/libQtCore.so.4.7.2'
  libname2 = libname[libname.rindex(os.path.sep)+1:libname.index('.so')+3]
  print libname2
  libqt = ctypes.CDLL(libname2)

  localmappings = getMappings()
  qtmaps = [m for m in localmappings if m.pathname is not None and libname2 in m.pathname ]

  myvaddr = qtmaps[0].start+offset

  ret = libdl.dladdr( myvaddr, ctypes.byref(info))
  print 'filling dlinfo with',libname, info

  signed_addr = libdl.dlsym( 0, 'dladdr', 'xxx')
  vaddr_dladdr = struct.unpack('L',struct.pack('l', signed_addr) )[0]
  ret = libdl.dladdr( vaddr_dladdr, ctypes.byref(info))
  print 'dlsym test', info.dli_sname.string, info.dli_sname.string == 'dladdr'

def test2():
  # now for the real deal.
  # we need to emulate ELF dl-addr.c 


  print ''

  #
  #define DL_LOOKUP_ADDRESS(addr) _dl_lookup_address (addr)

  libssl = ctypes.CDLL('/usr/lib/libssl.so.0.9.8')
  localmappings = getMappings()

  print 'libssl.ssl3_read by id() is @%x'%( id(libssl.ssl3_read) )
  print localmappings.getMmapForAddr(id(libssl.ssl3_read))

  print ''
  signed_addr = libssl.dlsym( libssl._handle, 'ssl3_read', 'xxx')
  fnaddr = struct.unpack('L',struct.pack('l', signed_addr) )[0]
  print 'libssl.ssl3_read by dlsym is @%x'%(fnaddr)
  print localmappings.getMmapForAddr(fnaddr)

  info = Dl_info()
  ret = libdl.dladdr( fnaddr, ctypes.byref(info))
  print 'dladdr test', info.dli_sname.string, info.dli_sname.string == 'ssl3_read'
  '''
libssl.ssl3_read by id() is @9528ecc
0x0924a000 0x095d1000 rw-p 0x00000000 00:00 0000000 [heap]

libssl.ssl3_read by dlsym is @b6ddd9b0
0xb6dc2000 0xb6e0c000 r-xp 0x00000000 08:04 7739090 /lib/libssl.so.0.9.8
dladdr test ssl3_read True
  '''
  print ''

  # testing low level
  # low level call 
  #(const void *address, Dl_info *info,
  #	  struct link_map **mapp, const ElfW(Sym) **symbolp)
  print libdl._dl_addr( fnaddr, ctypes.byref(info), 0, 0)
  # iterate the struct link_map
  #for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns)
  #  for (struct link_map *l = GL(dl_ns)[ns]._ns_loaded; l; l = l->l_next)
  #    if (addr >= l->l_map_start && addr < l->l_map_end
	#  && (l->l_contiguous || _dl_addr_inside_object (l, addr)))
  
  return


def test3():
  # load local memdump
  # map all librairies
  # go through all pointers in librairies
  # try to dl_addr the pointers by rebasing.
  from haystack import memory_loader
  dump = memory_loader.load('/home/jal/outputs/dumps/ssh/ssh.1.dump')


libdl = ctypes.CDLL('libdl.so')

def main(argv):
  #test1()
  #test2()
  test3()

if __name__ == '__main__':
  main(sys.argv[1:])




