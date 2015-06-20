#!/bin/sh

# Todo Makefile


# generate win XP x32 profiles
WinXPSP3X86/ntdll.pdb.dll
WinXPSP3X86/ntoskrnl.pdb.exe

pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/WinXPSP3X86/ntdll.pdb.dll > WinXPSP3X86.ntdll.32.h
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/WinXPSP3X86/ntoskrnl.pdb.exe > WinXPSP3X86.ntoskrnl.32.h

clang2py --target i386-win -o winxp_32.py WinXPSP3X86.ntdll.32.h WinXPSP3X86.ntoskrnl.32.h

# check
# for s in `cat heap.structures`; do x=`grep -c $s WinXPSP3X86.ntdll.32.h` ; echo -e "$x\t$s" ; done
# for s in `cat heap.structures`; do x=`grep -c $s WinXPSP3X86.ntoskrnl.32.h` ; echo -e "$x\t$s" ; done

# generate winxp/2003 x64 profiles
#ntdll.pdb.dll:2
#ntkrnlmp.pdb.exe:2
#ntoskrnl.pdb.exe:2
pdbtoh.py -g -w 8 -d heap.structures /home/other/outputs/pdb/Win2k3-XP64-X64/ntdll.pdb.dll > Win2k3-XP64-X64.ntdll.32.h
pdbtoh.py -g -w 8 -d heap.structures /home/other/outputs/pdb/Win2k3-XP64-X64/ntoskrnl.pdb.exe > Win2k3-XP64-X64.ntoskrnl.32.h

clang2py --target x86_64-win64 -o winxp_64.py Win2k3-XP64-X64.ntdll.32.h Win2k3-XP64-X64.ntoskrnl.32.h


# generate win7 x32 profiles
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/Win7SP1X86/_000160E > Win7SP1X86._000160E.32.h
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/Win7SP1X86/_00003BA > Win7SP1X86._00003BA.32.h

clang2py --target i386-win -o win7_32.py Win7SP1X86._000160E.32.h Win7SP1X86._00003BA.32.h


# generate win7 x64 profiles


pdbtoh.py -g -w 8 -d heap.structures /home/other/outputs/pdb/Win7SP1X64/_0000BEB > Win7SP1X64.0000BEB.64.h
pdbtoh.py -g -w 8 -d heap.structures /home/other/outputs/pdb/Win7SP1X64/_000143D > Win7SP1X64.000143D.64.h
# check
# for s in `cat heap.structures`; do x=`cat Win7SP1X64.*.64.h | grep -c $s` ; echo -e "$x\t$s" ; done
clang2py --target x86_64-win64 -o win7_64.py Win7SP1X64.0000BEB.64.h Win7SP1X64.000143D.64.h


$ grep -c UCR_DESCRIPTOR * | grep -v :0
_0000BEB:1
_000143D:1


HEAP
_00029A3:56
_00031F8:55

HEAP_SEGMENT
_0000BEB:2
_000143D:2

