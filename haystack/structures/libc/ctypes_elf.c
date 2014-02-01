/* from various elf libs http://www.tinyos.net/tinyos-1.x/tools/src/mspgcc-pybsl/elf.py */

#define EI_NIDENT 16
typedef struct Elf_Ehdr{
    unsigned char e_ident[EI_NIDENT];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int e_version;
    unsigned int e_entry;
    unsigned int  e_phoff;
    unsigned int  e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;
} Elf32_Ehdr;
