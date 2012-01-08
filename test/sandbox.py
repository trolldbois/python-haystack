
'''
	( 'ptr_ext_lib' , ctypes.c_void_p ), # @ b6b3ef68 /usr/lib/libQtCore.so.4.7.2 


local python
b6c63000-b6efa000 r-xp 00000000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4
b6efa000-b6f01000 r--p 00296000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4
b6f01000-b6f04000 rw-p 0029d000 08:04 3426931    /usr/lib/i386-linux-gnu/libQtCore.so.4.7.4

'''
import struct
import os
import ctypes

offset = 0xb6b3ef68 - 0xb68b1000

from haystack import memory_mapping, utils

class Dl_info(ctypes.Structure):
  _fields_ = [
  ('dli_fname', ctypes.c_char_p), #Pathname of shared object that contains address
  ('dli_fbase', ctypes.c_void_p), #Address at which shared object is loaded
  ('dli_sname', ctypes.c_char_p), #Name of nearest symbol with address lower than addr
  ('dli_saddr', ctypes.c_void_p)  #Exact address of symbol named in dli_sname
  ]
  

info = Dl_info()

libdl = ctypes.CDLL('libdl.so')
#handle = libdl.dlopen('/usr/lib/libQtCore.so.4.7.2')

libname = '/usr/lib/libQtCore.so.4.7.2'
libname2 = libname[libname.rindex(os.path.sep)+1:libname.index('.so')+3]
print libname2
libqt = ctypes.CDLL(libname2)

me = utils.Dummy()
me.pid = os.getpid()
localmappings = memory_mapping.readProcessMappings(me)
qtmaps = [m for m in localmappings if m.pathname is not None and libname2 in m.pathname ]

myvaddr = qtmaps[0].start+offset

ret = libdl.dladdr( myvaddr, ctypes.byref(info))
print info

signed_addr = libdl.dlsym( 0, 'dladdr', 'xxx')
vaddr_dladdr = struct.unpack('L',struct.pack('l', signed_addr) )[0]
ret = libdl.dladdr( vaddr_dladdr, ctypes.byref(info))
print info.dli_sname.string


import pattern 
pattern.main('outputs/skype.1.a outputs/skype.2.a outputs/skype.3.a'.split())
mapper = pattern.mapper

unresolved = pattern.mapper.unresolved
resolved = pattern.mapper.resolved

p1 = resolved[0]
p2 = resolved[1]
p3 = resolved[2]

pt1 = p1.sig.dump.readWord( p1.getAddress() )
pt1b = p1.sig.dump.readWord( p1.getAddress(1) )

pt1 in p1.sig.dump
pt1b in p1.sig.dump

pt2 = p2.sig.dump.readWord( p2.getAddress() )
pt3 = p3.sig.dump.readWord( p3.getAddress() )

ap1 = pattern.AnonymousStructRange(p1)
len(ap1)
ap.structLen()

b1 = p1.sig.dump.readBytes( p1.getAddress()-16, 32 )
cut =32
print b1.encode('hex')[0:cut],b1.encode('hex')[cut:]

p1.sig.dump.readWord

#b2 = p2.sig.dump.readBytes( p2.getAddress()-16, 32 )
#b3 = p3.sig.dump.readBytes( p3.getAddress()-16, 32 )

#print b2.encode('hex')[0:cut],b2.encode('hex')[cut:]
#print b3.encode('hex')[0:cut],b3.encode('hex')[cut:]



sig = mapper.signatures[0]
resolved_for_sig = [ pp for pp in mapper.resolved if pp.sig == sig ]
pinned = [pattern.AnonymousStructRange(pp) for pp in resolved_for_sig]
print('check for overlapping #not possible# on %d values '%(len(pinned)))
for i, pp in enumerate(pinned):
  if pp.stop in pinned[i+1:]:
    #print('OVERLAPPING PinnedPointers - THAT IS NOT POSSIBLE. WHO MESSED WITH MY CODE !')
    j = pinned[i+1:].index(pp.stop)
    c = pinned[i+1+j]
    #print pp.start, pp.stop, c.start, c.stop,
    print pp.pinnedPointer, c.pinnedPointer
    #print pp.stop in c
    #break
    












import itertools
allpp = sorted([v for l in mapper.cacheValues2.values() for v in l], reverse=True)
unresolved = []

for k, g in itertools.groupby( allpp ):
  l = list(g)
  if len(l) < len(mapper.signatures): # we can have multiple instances btu not less.
    unresolved.extend(l)
    #print 'not same numbers'
    continue
  else:
    # we should have all 3 signatures
    found = [pp.sig for pp in l ]
    for s in mapper.signatures:
      if s not in found:
        unresolved.extend(l)
        #print 'not same sigs', s
        break

unresolved.reverse()

print 'left with %d/%d unresolved pp'%(len(unresolved), len(allpp) )

## we are left with pp present in less than all sigs.

a=unresolved[:10]
for p in a:
  print p



print '%s not in found'%(s) 
print 'we have to find a PinnedPointer related to size %s and %s'%(k, ['%s'%pp for pp in v])

