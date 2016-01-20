# -*- coding: utf-8 -*-
class IMemoryMapping(object):
    """Interface for a memory mapping.
    A IMemoryMapping should hold one of a process memory _memory_handler and its start and stop addresses.
    """

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

    def read_array(self, address, basetype, count):
        """Reads the memory content at address <address> and returns an typed array.

        :param address: long the virtual address.
        :param basetype: a ctypes class.
        :param count: long the size of the array.
        :return: the memory content at address, in an array form
        :rtype: (basetype*count) ctypes class
        """
        raise NotImplementedError(self)

    def read_bytes(self, address, size):
        """Reads the memory content at address <address> and returns an array of bytes in a str.

        :param address: long the virtual address.
        :param size: long the size of the array.
        :return: the memory content at address, in an bytes string
        :rtype: str
        """
        raise NotImplementedError(self)

    def read_cstring(self, address, max_size, chunk_length=256):
        """Reads the memory content at address <address> and returns a python representation
        of the NULL terminated string.

        :param address: long the virtual address.
        :param max_size: long the maximum size of the string.
        :param chunk_length: (optional) long the number of bytes read at each buffer read.
        :return: the memory content at address, in an bytes string
        :rtype: str
        """
        raise NotImplementedError(self)

    def read_struct(self, address, struct):
        """Reads the memory content at address <address> and returns an ctypes record instance.

        :param address: long the virtual address.
        :param struct: a ctypes class.
        :return: the memory content at address, in an ctypes record form
        :rtype: (struct) ctypes class
        """
        raise NotImplementedError(self)

    def read_word(self, address):
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


class IMemoryLoader(object):
    """Parse a process memory _memory_handler from a storage concept,
    then identify its ITargetPlatform characteristics
    and produce an IMemoryHandler for this process memory dump """

    def make_memory_handler(self):
        """Returns an instance of IMemoryHandler """
        raise NotImplementedError(self)


class IMemoryHandler(object):
    """Interface for the MemoryHandler class."""

    def get_name(self):
        """Returns the name of the process memory dump we are analysing"""
        raise NotImplementedError(self)

    # helper methods that do not impact the internals
    def get_target_platform(self):
        """Returns the ITargetPlatform for that process memory."""
        raise NotImplementedError(self)

    def get_heap_finder(self):
        """Returns the IHeapFinder for that process memory."""
        raise NotImplementedError(self)

    def get_model(self):
        """Returns the Model cache."""
        raise NotImplementedError(self)

    # class proper methods
    def get_mappings(self):
        """
        return the list of IMemoryMapping
        :return: list of IMemoryMapping
        """
        raise NotImplementedError(self)

    def reset_mappings(self):
        """
        Temporarly closes all file used by this handler.
        :return:
        """
        raise NotImplementedError(self)

    # reverse helper
    def get_reverse_context(self):
        raise NotImplementedError(self)

    def get_mapping_for_address(self, vaddr):
        """Returns the IMemoryMapping that contains this virtual address."""
        raise NotImplementedError(self)

    def iter_mapping_with_name(self, pathname):
        """Returns the IMemoryMapping _memory_handler with the name pathname"""
        raise NotImplementedError(self)

    def is_valid_address(self, obj, struct_type=None):
        """Return true is the virtual address is a valid address in a IMemoryMapping"""
        raise NotImplementedError(self)

    def is_valid_address_value(self, addr, struct_type=None):
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

    def hasRef(self, typ, orig_addr):
        """Check if this type has already been loaded at this address"""
        raise NotImplementedError(self)

    def getRef(self, typ, orig_addr):
        """Returns the reference to the type previously loaded at this address"""
        raise NotImplementedError(self)

    def getRefByAddr(self, addr):
        raise NotImplementedError(self)

    def keepRef(self, obj, typ=None, orig_addr=None):
        """Keeps a reference for an object of a specific type loaded from a specific
        address.

        Sometypes, your have to cast a c_void_p, You can keep ref in Ctypes object,
           they might be transient (if obj == somepointer.contents)."""
        # TODO, memory leak for different objects of same size, overlapping
        # struct.
        raise NotImplementedError(self)

    def delRef(self, typ, orig_addr):
        """Forget about a Ref."""
        raise NotImplementedError(self)


class ITargetPlatform(object):
    """The guest platform information for the process memory handled by IMemoryHandler.
    Immutable, its characteristics should be set once at creation time.
    """

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
        """Returns the ctypes proxy instance adequate for the target process' platform """
        raise NotImplementedError(self)

    def get_target_ctypes_utils(self):
        """Returns the ctypes utils instance with additional ctypes helper method

        :rtype: ICTypesUtils"""
        raise NotImplementedError(self)

    def get_os_name(self):
        """Returns the name of the host platform"""
        raise NotImplementedError(self)

    def get_cpu_bits(self):
        """Returns the cpu bits of the host platform"""
        raise NotImplementedError(self)


class IHeapFinder(object):
    """
    Parse the IMemoryHandler's list of IMemoryMapping to find process Heaps.
    The IHeapFinder needs to be initialized with a IMemoryHandler.
    """

    def list_heap_walkers(self):
        """
        Return the list of heaps that load as heaps

        :return: list of IMemoryMapping
        """
        raise NotImplementedError(self)

    def get_heap_module(self):
        """
        Returns the heap module.
        :return: module
        """
        raise NotImplementedError(self)

    def get_heap_walker(self, heap):
        """
         return a IHeapWalker for that heap

        :param heap: IMemoryMapping
        :return: IHeapWalker
        """
        raise NotImplementedError(self)


class IHeapWalker(object):
    """
    Parse a heap IMemoryMapping for chunks of allocated memory or free chunks in the heap.
    The IHeapWalker needs to be initialized with a IMemoryHandler and a IMemoryMapping
    """
    def get_target_platform(self):
        """Returns the ITargetPlatform for that process memory Heap."""
        raise NotImplementedError(self)

    def get_heap_address(self):
        """ returns the address of the used heap """
        raise NotImplementedError('Please implement all methods')

    def get_user_allocations(self):
        """ returns all User allocations (addr,size) """
        raise NotImplementedError('Please implement all methods')

    def get_free_chunks(self):
        """ returns all free chunks in the heap (addr,size) """
        raise NotImplementedError('Please implement all methods')


class ICTypesUtils(object):
    """
    Some additional helper methods for ctypes
    """

    def formatAddress(self, addr):
        raise NotImplementedError('Please implement all methods')

    def unpackWord(self, bytes, endianess):
        raise NotImplementedError('Please implement all methods')

    def is_address_local(self, obj, structType):
        """
        Costly , checks if obj is mapped to local memory space.
        Returns the memory mapping if found.
        False, otherwise.
        """
        raise NotImplementedError('Please implement all methods')

    def get_pointee_address(self, obj):
        """
        Returns the address of the struct pointed by the obj, or null if invalid.

        :param obj: a pointer.
        """
        raise NotImplementedError('Please implement all methods')

    def container_of(self, memberaddr, typ, membername):
        """
        From a pointer to a member, returns the parent struct.
        Returns the instance of typ(), in which the member "membername' is really.
        Useful in some Kernel linked list which used members as prec,next pointers.

        :param memberadd: the address of membername.
        :param typ: the type of the containing structure.
        :param membername: the membername.

        Stolen from linux kernel headers.
             const typeof( ((typ *)0)->member ) *__mptr = (ptr);
            (type *)( (char *)__mptr - offsetof(type,member) );})
        """
        raise NotImplementedError('Please implement all methods')

    def offsetof(self, typ, membername):
        """
        Returns the offset of a member in a structure.

        :param typ: the structure type.
        :param membername: the membername in that structure.
        """
        raise NotImplementedError('Please implement all methods')

    def ctypes_to_python_array(self, array):
        """Converts an array of undetermined Basic self.__ctypes class to a python array,
        by guessing it's type from it's class name.

        This is a bad example of introspection.
        """
        raise NotImplementedError('Please implement all methods')

    def array2bytes(self, array):
        """Converts an array of undetermined Basic self.__ctypes class to a byte string,
        by guessing it's type from it's class name.

        This is a bad example of introspection.
        """
        raise NotImplementedError('Please implement all methods')

    def bytes2array(self, bytes, typ):
        """Converts a bytestring in a self.__ctypes array of typ() elements."""
        raise NotImplementedError('Please implement all methods')

    def pointer2bytes(self, attr, nbElement):
        """
        Returns an array from a self.__ctypes POINTER, given the number of elements.

        :param attr: the structure member.
        :param nbElement: the number of element in the array.
        """
        raise NotImplementedError('Please implement all methods')

    def get_subtype(self, cls):
        """get the subtype of a pointer, array or basic type with haystack quirks."""
        raise NotImplementedError('Please implement all methods')


class IConstraintsConfigHandler(object):
    """Handles constraints as specific in a file"""

    def read(self, filename):
        """

        :param filename:
        :return:
        """


class IModuleConstraints(object):
    """Defines the constraints configuration for a number of records.
    Each structure is associated to a list of constraint per field of that record.
    x = IModuleConstraints()
    [...[

    x['struct_1'] contains a dict()
    x['struct_1']['field1'] contains a list of contraints.
    """

    def get_constraints(self):
        """
        get the list of record_type_name,IConstraint for all fields of
        :return dict
        """
        raise NotImplementedError('Please implement all methods')

    def set_constraints(self, record_type_name, record_constraints):
        """
        Add constraints for that record_type name
        :param record_type_name:
        :param record_constraints:
        :return
        """
        raise NotImplementedError('Please implement all methods')

    def get_dynamic_constraints(self):
        """
        get the record_type_name,IRecordTypeDynamicConstraintsValidator

        :return dict
        """
        raise NotImplementedError('Please implement all methods')

    def set_dynamic_constraints(self, record_type_name, record_constraints):
        """
        Add dynamic constraints validator for that record_type name
        :param record_type_name: str
        :param record_constraints: IRecordTypeDynamicConstraintsValidator
        :return:
        """
        raise NotImplementedError('Please implement all methods')


class IRecordConstraints(object):
    """
    Holds the constraints for fields of a specific record type.
    """

    def get_fields(self):
        """get the list of field names."""
        raise NotImplementedError('Please implement all methods')

    def get_constraints_for_field(self, field_name):
        """get the list of IConstraint for a field"""
        raise NotImplementedError('Please implement all methods')


class IConstraint(object):
    """
    Defines a constraint validation test for a field.
    Class must implement contains.

    The test is : "if attr not in <IConstraint instance>"
    """

    def __contains__(self, obj):
        raise NotImplementedError('Please implement all methods')


class IRecordConstraintsValidator(object):
    """
    The worker class that validates all cp
    """

    def is_valid(self, record):
        """
        Checks if each member field of record has coherent data
        with the constraints that exists for this record

        For each Field, check on of the three case,
            a) basic types (check for expectedValues),
                if field as some expected values in expectedValues
                     check field value against expectedValues[fieldname]
                     if False, return False, else continue

            b) struct(check isValid)
                check if the inner struct isValid()
                if False, return False, else continue

            c) is an array , recurse validation

            d) Pointer(check valid_address or expectedValues is None == NULL )
                if field as some expected values in expectedValues
                    ( None or 0 ) are the only valid options to design NULL pointers
                     check field get_pointee_address() value against expectedValues[fieldname] // if NULL
                            if True(address is NULL and it's a valid value), continue
                     check get_pointee_address against is_valid_address()
                            if False, return False, else continue
        """
        raise NotImplementedError('Please implement all methods')

    def load_members(self, record, max_depth):
        """

        :param record:
        :param max_depth:
        :return:
        """
        raise NotImplementedError('Please implement all methods')


class IRecordTypeDynamicConstraintsValidator(object):
    """
    A record-type-based constraints validation class
    """
    def get_record_type_name(self):
        """Return the name of the record_type for which these advanced checks can occur"""
        raise NotImplementedError('Please implement all methods')

    def is_valid(self, record):
        """
        Advanced checks that cannot be expressed in the constraints files
        """
        raise NotImplementedError('Please implement all methods')

    # TODO get_list_tuples