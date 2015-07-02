
class IMemoryMapping(object):
    """Interface for a memory mapping"""

    def _vtop(self, vaddr):
        """Translates the virtual address to a physical address from the underlying storage.

        :param vaddr: long the virtual address.
        :return: the physical address in the underlying storage object for a virtual address
        :rtype: long
        """
        raise NotImplementedError(self)

    def _ptov(self, paddr):
        """Translates the physical address from the underlying storage to a virtual address.

        :param paddr: long the physical address.
        :return: the virtual address in the process memory from the physical address
        :rtype: long
        """
        raise NotImplementedError(self)

    def readArray(self, address, basetype, count):
        """Reads the memory content at address <address> and returns an typed array.

        :param address: long the virtual address.
        :param basetype: a ctypes class.
        :param count: long the size of the array.
        :return: the memory content at address, in an array form
        :rtype: (basetype*count) ctypes class
        """
        raise NotImplementedError(self)

    def readBytes(self, address, size):
        """Reads the memory content at address <address> and returns an array of bytes in a str.

        :param address: long the virtual address.
        :param size: long the size of the array.
        :return: the memory content at address, in an bytes string
        :rtype: str
        """
        raise NotImplementedError(self)

    def readCString(self, address, max_size, chunk_length=256):
        """Reads the memory content at address <address> and returns a python representation
        of the NULL terminated string.

        :param address: long the virtual address.
        :param max_size: long the maximum size of the string.
        :param chunk_length: (optional) long the number of bytes read at each buffer read.
        :return: the memory content at address, in an bytes string
        :rtype: str
        """
        raise NotImplementedError(self)

    def readStruct(self, address, struct):
        """Reads the memory content at address <address> and returns an ctypes record instance.

        :param address: long the virtual address.
        :param struct: a ctypes class.
        :return: the memory content at address, in an ctypes record form
        :rtype: (struct) ctypes class
        """
        raise NotImplementedError(self)

    def readWord(self, address):
        """Reads the memory content at address <address> and returns an word worth of it.
        Usually 4 or 8 bytes.

        :param address: long the virtual address.
        :return: the memory content at address, in an bytes string
        :rtype: str
        """
        raise NotImplementedError(self)

    def search(self, bytestr):
        """Search the memory for this particular sequence of bytes and iterates over the starting
        address of the results.

        :param bytestr: bytes str, the sequence of bytes to look for.
        :return: (iterator) long, the list of virtual address matching the byte pattern
        :rtype: iterator, long, the starting virtual address of the match
        """
        raise NotImplementedError(self)

    def __contains__(self, address):
        raise NotImplementedError(self)

    def __len__(self):
        raise NotImplementedError(self)


class IMemory(object):
    """Interface for the Memory class."""

    def get_mapping_for_address(self, vaddr):
        """Returns the IMemoryMapping that contains this virtual address."""
        raise NotImplementedError(self)

    def iter_mapping_with_name(self, pathname):
        """Returns the IMemoryMapping mappings with the name pathname"""
        raise NotImplementedError(self)

    def get_heap(self):
        """Returns the first IMemoryMapping heaps"""
        raise NotImplementedError(self)

    def get_heaps(self):
        """Returns all IMemoryMapping heaps"""
        raise NotImplementedError(self)

    def get_stack(self):
        """Returns the IMemoryMapping identified as the stack"""
        raise NotImplementedError(self)

    def is_valid_address(self, obj, structType=None):
        """Return true is the virtual address is a valid address in a IMemoryMapping"""
        raise NotImplementedError(self)

    def is_valid_address_value(self, addr, structType=None):
        """Return true is the virtual address is a valid address in a IMemoryMapping"""
        raise NotImplementedError(self)

    def __contains__(self, vaddr):
        """Return true is the virtual address is a valid address in a IMemoryMapping"""
        raise NotImplementedError(self)

    def __len__(self):
        """Return the number of IMemoryMapping"""
        raise NotImplementedError(self)

    def __getitem__(self, i):
        raise NotImplementedError(self)

    def __setitem__(self, i, val):
        raise NotImplementedError(self)

    def __iter__(self):
        raise NotImplementedError(self)


class IMemoryCache(object):
    """Interface for the MemoryCache class.
    Usage 1:
     + when one uses the model to load a record from the underlying memory, the record
     can be cached as to improve performance:
        - memory storage could be slow like in ProcessMemoryMapping

    Usage 2:
     + one can ou this cache to store plain old python object equivalent of ctypes record
     when translating memory structure in python class, json, or other
        - circular dependencies can be resolved
    """

    def reset(self):
        """Clean the book"""
        raise NotImplementedError(self)

    def getRefs(self):
        """Lists all references to already loaded structs. Useful for debug"""
        raise NotImplementedError(self)

    def printRefs(self):
        """Prints all references to already loaded structs. Useful for debug"""
        raise NotImplementedError(self)

    def printRefsLite(self):
        """Prints all references to already loaded structs. Useful for debug"""
        raise NotImplementedError(self)

    def hasRef(self, typ, origAddr):
        """Check if this type has already been loaded at this address"""
        raise NotImplementedError(self)

    def getRef(self, typ, origAddr):
        """Returns the reference to the type previously loaded at this address"""
        raise NotImplementedError(self)

    def getRefByAddr(self, addr):
        raise NotImplementedError(self)

    def keepRef(self, obj, typ=None, origAddr=None):
        """Keeps a reference for an object of a specific type loaded from a specific
        address.

        Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object,
           they might be transient (if obj == somepointer.contents)."""
        # TODO, memory leak for different objects of same size, overlapping
        # struct.
        raise NotImplementedError(self)

    def delRef(self, typ, origAddr):
        """Forget about a Ref."""
        raise NotImplementedError(self)

class ITargetPlatform(object):
    """The Memory guest platform information. Immutable."""

    def get_word_type(self):
        """Returns the memory guest word base ctypes type (int21 or int4) """
        raise NotImplementedError(self)

    def get_word_type_char(self):
        """Returns the memory guest word base ctypes character (I or Q) """
        raise NotImplementedError(self)

    def get_word_size(self):
        """Returns the memory guest word base ctypes type size (4 or 8) """
        raise NotImplementedError(self)

    def get_target_ctypes(self):
        """Returns the ctypes proxy instance """
        raise NotImplementedError(self)
