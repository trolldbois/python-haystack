# -*- coding: utf-8 -*-
import ctypes


class struct_Elf_Ehdr(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('e_ident', ctypes.c_ubyte * 16),
        ('e_type', ctypes.c_uint16),
        ('e_machine', ctypes.c_uint16),
        ('e_version', ctypes.c_uint32),
        ('e_entry', ctypes.c_uint32),
        ('e_phoff', ctypes.c_uint32),
        ('e_shoff', ctypes.c_uint32),
        ('e_flags', ctypes.c_uint32),
        ('e_ehsize', ctypes.c_uint16),
        ('e_phentsize', ctypes.c_uint16),
        ('e_phnum', ctypes.c_uint16),
        ('e_shentsize', ctypes.c_uint16),
        ('e_shnum', ctypes.c_uint16),
        ('e_shstrndx', ctypes.c_uint16),
    ]

Elf32_Ehdr = struct_Elf_Ehdr

__all__ = ['Elf32_Ehdr', 'struct_Elf_Ehdr']
