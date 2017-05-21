# -*- coding: utf-8 -*-
import logging
import platform
import struct
import sys

from haystack import types
from haystack import utils
from haystack.abc import interfaces


log = logging.getLogger("target")

# triplet = getattr(sys, 'implementation', sys)._multiarch
# arch vendor os
# FIXME use it
TARGET_TRIPLETS = [
    ('i386-linux-gnu', (4, 4, 12)),
    ('x86_64-linux-gnu', (8, 8, 16)),
    ('i386-pc-win', (4, 4, 8)),
    ('x86_64-pc-win', (8, 8, 8)),
]


class TargetPlatform(interfaces.ITargetPlatform):
    """The guest platform information for the process memory handled by IMemoryHandler.
    Immutable, its characteristics should be set once at creation time.
    """
    WINXP = 'winxp'
    WIN7 = 'win7'
    LINUX = 'linux'

    def __init__(self, mappings, os_name=None, cpu_bits=None, word_size=None, ptr_size=None, ld_size=None):
        if mappings is None:
            # we cant detect the os_name and cpu_bits without _memory_mappings
            assert os_name is not None and cpu_bits is not None
        elif not isinstance(mappings, list):
            raise TypeError("list of IMemoryMapping expected")
        elif len(mappings) == 0:
            raise TypeError("list with at least one IMemoryMapping expected")
        elif not isinstance(mappings[0], interfaces.IMemoryMapping):
            raise TypeError("IMemoryMapping list expected")
        self.__os_name = os_name or self._detect_os(mappings)
        self.__cpu_bits = cpu_bits or self._detect_cpu(mappings, self.__os_name)
        self.__word_size = word_size or self._detect_word_size()
        self.__ptr_size = ptr_size or self._detect_ptr_size()
        self.__ld_size = ld_size or self._detect_ld_size()  # long double
        # win  32 bits, 4,4,8
        # linux 32 bits, 4,4,12
        # linux 64 bits, 8,8,16
        self.__ctypes_proxy = types.build_ctypes_proxy(self.__word_size, self.__ptr_size, self.__ld_size)
        pass

    def get_os_name(self):
        return self.__os_name

    def get_cpu_bits(self):
        return self.__cpu_bits

    def get_target_ctypes(self):
        """Returns the ctypes proxy instance adequate for the target process' platform """
        return self.__ctypes_proxy

    def get_target_ctypes_utils(self):
        """Returns the ctypes proxy instance adequate for the target process' platform """
        return utils.Utils(self.__ctypes_proxy)

    def get_word_size(self):
        return self.__word_size

    def get_word_type(self):
        if self.get_word_size() == 4:
            return self.__ctypes_proxy.c_uint32
        elif self.get_word_size() == 8:
            return self.__ctypes_proxy.c_uint64
        else:
            raise ValueError('platform not supported for word size == %d' % (self.get_word_size()))

    def get_word_type_char(self):
        if self.get_word_size() == 4:
            return 'I'
        elif self.get_word_size() == 8:
            return 'Q'
        else:
            raise ValueError(
                'platform not supported for word size == %d' %
                (self.get_word_size()))

    def __str__(self):
        return 'Target: OS:%s CPU:%s WordSize:%d' % (self.get_os_name(), self.get_cpu_bits(), self.get_word_size())

    @classmethod
    def _detect_os(cls, mappings):
        """Arch independent way to assess the os of a captured process"""
        scores = {'linux': 0, 'winxp': 0, 'win7': 0}
        for pathname in [m.pathname.lower() for m in mappings
                         if m.pathname is not None and m.pathname != '']:
            if '\\system32\\' in pathname:
                scores['winxp'] += 1
                scores['win7'] += 1
            if 'ntdll.dll' in pathname:
                scores['winxp'] += 1
                scores['win7'] += 1
            elif 'Documents and Settings' in pathname:
                scores['winxp'] += 1
            elif 'xpsp2res.dll' in pathname:
                scores['winxp'] += 1
            elif 'SysWOW64' in pathname:
                scores['win7'] += 1
            elif '\\wer.dll' in pathname:
                scores['win7'] += 1
            elif '[heap]' in pathname:
                scores['linux'] += 1
            elif '[vdso]' in pathname:
                scores['linux'] += 1
            elif '/usr/lib/' in pathname:
                scores['linux'] += 1
            elif '/' == pathname[0]:
                scores['linux'] += 1
        for m in mappings:
            # winxp versus win7 - try out heap Signature
            for os_name, bits, offset in [('winxp', 32, 8), ('winxp', 64, 16), ('win7', 32, 100), ('win7', 64, 160)]:
                signature = struct.unpack('I', m.read_bytes(m.start+offset, 4))[0]
                if signature == 0xeeffeeff:
                    scores[os_name] += 1
        # if nothing is found that way, try pefile detection
        # volatility case usually
        if scores.values() == [0, 0, 0]:
            try:
                cls._detect_cpu_arch_pe(mappings)
                scores['winxp'] += 1
                scores['win7'] += 1
            except NotImplementedError as e:
                pass
            try:
                cls._detect_cpu_arch_elf(mappings)
                scores['linux'] += 1
            except NotImplementedError as e:
                pass

        log.debug('detect_os: scores linux:%d winxp:%d win7:%d', scores['linux'], scores['winxp'], scores['win7'])
        res = sorted(scores.items(), key=lambda x: x[1], reverse=True)[0]
        if res[0] == 'linux':
            return cls.LINUX
        elif res[0] == 'winxp':
            return cls.WINXP
        elif res[0] == 'win7':
            return cls.WIN7

    @classmethod
    def _detect_cpu(cls, mappings, os_name=None):
        if os_name is None:
            os_name = cls._detect_os(mappings)
        cpu = 'unknown'
        if os_name == cls.LINUX:
            cpu = cls._detect_cpu_arch_elf(mappings)
        elif os_name == cls.WINXP or os_name == cls.WIN7:
            cpu = cls._detect_cpu_arch_pe(mappings)
        return cpu

    @classmethod
    def _detect_cpu_arch_pe(cls, mappings):
        import pefile
        # get the maps with read-only data
        # find the executable image and get the PE header
        pe = None
        for m in mappings:
            # volatility dumps VAD differently than winappdbg
            # we have to look at all _memory_handler
            # if m.permissions != 'r--':
            #    continue
            try:
                head = m.read_bytes(m.start, 0x1000)
                pe = pefile.PE(data=head, fast_load=True)
                # only get the First one that works
                if pe is None:
                    continue
                break
            except pefile.PEFormatError as e:
                pass
        machine = pe.FILE_HEADER.Machine
        arch = pe.OPTIONAL_HEADER.Magic
        if arch == 0x10b:
            return 32
        elif arch == 0x20b:
            return 64
        else:
            raise NotImplementedError('MACHINE is %s' % machine)

    @classmethod
    def _detect_cpu_arch_elf(cls, mappings):
        from haystack.allocators.libc.ctypes_elf import struct_Elf_Ehdr
        # find an executable image and get the ELF header
        for m in mappings:
            # FIXME
            if 'r-xp' not in m.permissions:
                continue
            #head = m.read_bytes(m.start, 0x40)  # 0x34 really
            try:
                head = m.read_bytes(m.start, 0x40)  # 0x34 really
            except Exception as e:
                log.debug('read_bytes failed '+ str(e))
                raise e
            x = struct_Elf_Ehdr.from_buffer_copy(head)
            log.debug('MACHINE:%s pathname:%s' % (x.e_machine, m.pathname))
            if x.e_machine == 3:
                return 32
            elif x.e_machine == 62:
                return 64
            else:
                continue
        raise NotImplementedError('MACHINE has not been found.')

    def _detect_ptr_size(self):
        # by default, we only handle this
        return self.__cpu_bits//8

    def _detect_word_size(self):
        # by default, we only handle this
        return self.__cpu_bits//8

    def _detect_ld_size(self):
        # win  32 bits, 4,4,8
        # linux 32 bits, 4,4,12
        # linux 64 bits, 8,8,16
        if self.__os_name in [self.WINXP, self.WIN7]:
            return 8
        elif self.__os_name == self.LINUX and self.__word_size == 4:
            return 12
        return 16

    @staticmethod
    def make_target_platform_local():
        return _make_target_platform_local()

    @staticmethod
    def make_target_win_32(os_name):
        """    """
        if os_name not in ['winxp', 'win7']:
            raise TypeError('os_name should be winxp or win7')
        target = TargetPlatform(None, os_name=os_name, cpu_bits=32, word_size=4, ptr_size=4, ld_size=8)
        return target

    @staticmethod
    def make_target_win_64(os_name):
        """    """
        if os_name not in ['winxp', 'win7']:
            raise TypeError('os_name should be winxp or win7')
        target = TargetPlatform(None, os_name=os_name, cpu_bits=64, word_size=8, ptr_size=8, ld_size=8)
        return target

    @staticmethod
    def make_target_linux_32():
        """    """
        target = TargetPlatform(None, os_name=TargetPlatform.LINUX, cpu_bits=32, word_size=4, ptr_size=4, ld_size=12)
        return target

    @staticmethod
    def make_target_linux_64():
        """    """
        target = TargetPlatform(None, os_name=TargetPlatform.LINUX, cpu_bits=64, word_size=8, ptr_size=8, ld_size=16)
        return target


__LOCAL_PLATFORM = None


def _make_target_platform_local():
    """
    module platform is very slow. We need to cache the information.
    The local platform will not change in between calls :)
    """
    global __LOCAL_PLATFORM
    if __LOCAL_PLATFORM:
        return __LOCAL_PLATFORM
    cpu = int(platform.architecture()[0].split('bit')[0])
    if 'linux' in sys.platform:
        os_name = TargetPlatform.LINUX
    else: # sys.platform.startswith('win'):
        os_name = TargetPlatform.WIN7
    if cpu == 32:
        if os_name in [TargetPlatform.WINXP, TargetPlatform.WIN7]:
            __LOCAL_PLATFORM = TargetPlatform.make_target_win_32(os_name)
        elif os_name == TargetPlatform.LINUX:
            __LOCAL_PLATFORM = TargetPlatform.make_target_linux_32()
    elif cpu == 64:
        if os_name in [TargetPlatform.WINXP, TargetPlatform.WIN7]:
            __LOCAL_PLATFORM = TargetPlatform.make_target_win_64(os_name)
        elif os_name == TargetPlatform.LINUX:
            __LOCAL_PLATFORM = TargetPlatform.make_target_linux_64()
    return __LOCAL_PLATFORM
