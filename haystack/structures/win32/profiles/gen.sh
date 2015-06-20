#!/bin/sh

# Todo Makefile


# generate win XP x32 profiles
WinXPSP3X86/ntdll.pdb.dll
WinXPSP3X86/ntoskrnl.pdb.exe

pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/WinXPSP3X86/ntdll.pdb.dll > WinXPSP3X86.ntdll.32.h
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/WinXPSP3X86/ntoskrnl.pdb.exe > WinXPSP3X86.ntoskrnl.32.h

clang2py --target i386 -o winxp_32.py WinXPSP3X86.ntdll.32.h WinXPSP3X86.ntoskrnl.32.h

# check
# for s in `cat heap.structures`; do x=`grep -c $s WinXPSP3X86.ntdll.32.h` ; echo -e "$x\t$s" ; done
# for s in `cat heap.structures`; do x=`grep -c $s WinXPSP3X86.ntoskrnl.32.h` ; echo -e "$x\t$s" ; done

# generate x64 profiles


# generate win7 x32 profiles
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/Win7SP1X86/_000160E > Win7SP1X86._000160E.32.h
pdbtoh.py -g -w 4 -d heap.structures /home/other/outputs/pdb/Win7SP1X86/_00003BA > Win7SP1X86._00003BA.32.h

clang2py --target i386 -o win7_32.py Win7SP1X86._000160E.32.h Win7SP1X86._00003BA.32.h
