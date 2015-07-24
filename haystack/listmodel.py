# -*- coding: utf-8 -*-
#
"""
    Extension for list grammars.

"""
__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Beta"


"""
You have to use one of the Helpers function:

    declare_double_linked_list_type(structType, forward, backward)



"""

import ctypes
import logging

from haystack import basicmodel

log = logging.getLogger('listmodel')


class ListModel(basicmodel.CTypesRecordConstraintValidator):

    """
    Helpers to support records with linked list members.

    _listMember_:

    If this record type A has a pointer member 'next' that points to the
    address of another instance of the record type A (offset 0) then you should
    add this member name in the list _listMember_.

        A._listMember_ = ['next']

    C code example:
    struct A {
        int a;
        struct A * next;
    }



    _listHead_:

    If this record type A has a pointer member 'flink' that points to a member
    of another record type B - or to a non-offset-0 member of another instance
    of A - then you should add an entry in the list _listHead_ with the tuple:
        (fieldname,structType,structFieldname,offset)

        struct_Entry._listHead_ = [ ('flink', struct_A, 'list', -4),
                                    ('blink', struct_A, 'list', -4)]

    C code example:
    struct Entry {
        struct Entry * flink;
        struct Entry * blink;
    }
    struct A {
        int a;
        struct Entry list;
        int b;
    }


    """
    _listMember_ = []  # members that are the 2xpointer of same type linl
    #_listHead_ = []  # head structure of a linkedlist

    _double_link_list_types = dict()
    _list_heads = dict()

    def register_double_linked_list_type(self, record_type, forward, backward):
        """
        Declares a structure to be a double linked list management structure.

        register_double_linked_list_type(struct_Entry, 'next', 'previous')

        C code example:
            struct Entry {
                struct Entry * next;
                struct Entry * previous;
            }

        Most of the time, these structure type are used as fields of a parent struct_A
        record as to either:
         a) maintain a list of struct_B elements/children
         b) chain to a list of struct_A siblings

        The difference between case a) and b) is handled by the following function

          register_list_field_and_type(struct_type, field_name, list_entry_type, list_entry_field_name, offset)

        Impacts:
        The effect will be the structure type's instance will NOT be validated, or loaded
        by the ListModel Constraints validator.
        No member, pointers members will be loaded.
        But elements of the list can be iterated upon with ListModel.iterate_list,
        At what point, address validation of both forward and backward pointer
        occurs before loading of pointee elements.

        :param record_type: the ctypes.Structure type that holds double linked list pointers fields
        :param forward: the forward pointer
        :param backward: the backward pointer
        :return: None
        """
        if not issubclass(record_type, ctypes.Structure):
            raise TypeError('Feed me a ctypes.Structure')
        # test field existences in instance
        flink_type = getattr(record_type, forward)
        blink_type = getattr(record_type, backward)
        # test field existences in type
        d = dict(basicmodel.get_fields(record_type))
        flink_type = d[forward]
        blink_type = d[backward]
        if not self._ctypes.is_pointer_type(flink_type):
            raise TypeError('The %s field is not a pointer.', forward)
        if not self._ctypes.is_pointer_type(blink_type):
            raise TypeError('The %s field is not a pointer.', backward)
        # ok - save that structure information
        self._double_link_list_types[record_type] = (forward, backward)
        return

    # FIXME: offset is redundant. It should be calculated vy target_ctypes.offsetof(list_entry_field_name)
    # FIXME offset == utils.offsetof(type(self), fieldname)
    def register_list_field_and_type(self, record_type, field_name, list_entry_type, list_entry_field_name, offset):
        """
        Register the member <field_name> of a <struct_type> record type,
        to be of the starting point of a list of <list_entry_type> record types.
        The list member are referenced by the address of field <list_entry_field_name> in <list_entry_type>

        The field_name type should have been previously registered with this ListModel.

        C code example:
            struct Entry {
                struct Entry * next;
                struct Entry * previous;
            }

            struct Node {
                int hi;
                struct Entry list;
            }

            struct Child {
                float c;
                struct Entry siblings;
            }

        Python code example:
        In the case of a list of siblings:
            register_double_linked_list_type(struct_Entry, 'next', 'previous')
            register_list_field_and_type(struct_Node, 'list', struct_Node, 'list')

        In the case of a list of child elements with siblings:
            register_double_linked_list_type(struct_Entry, 'next', 'previous')
            register_list_field_and_type(struct_Node, 'list', struct_Child, 'siblings')
            register_list_field_and_type(struct_Child, 'siblings', struct_Child, 'siblings')

        :param record_type: a ctypes record type
        :param field_name:
        :param list_entry_type:
        :param list_entry_field_name:
        :return:
        """
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a ctypes record type')
        #
        if record_type not in self._list_heads:
            self._list_heads[record_type] = dict()
        self._list_heads[record_type][field_name] = (list_entry_type, list_entry_field_name, offset)

    def get_list_heads(self, record_type):
        if isinstance(record_type, ctypes.Structure) or isinstance(record_type, ctypes.Union):
            raise TypeError('Feed me a type not an instance')
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a record type')
        mro = list(record_type.__mro__[:-3]) # cut Structure, _CData and object
        mro.reverse()
        me = mro.pop(-1)
        for typ in mro:  # firsts are first, cls is in here in [-1]
            if typ not in self._list_heads:
                continue
            for field_name, entries in self._list_heads[typ].items():
                yield (field_name, entries[0], entries[1], entries[2])


    def _load_list_entries(self, record, fieldname, max_depth):
        """
        we need to load the pointed entry as a valid struct at the right offset,
        and parse it.

        When does it stop following FLink/BLink ?
            sentinel is headAddr only
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')

        structType, offset = self._get_list_field_info(fieldname)
        # FIXME offset == utils.offsetof(type(self), fieldname)
        # DO NOT think HEAD is a valid entry.
        # if its a ListEntries, self has already been loaded anyway.
        headAddr = record._orig_address_ + self._utils.offsetof(type(record), fieldname)
        head = getattr(record, fieldname)

        for entry in self._iterate_list(head):
            # DO NOT think HEAD is a valid entry
            if entry == headAddr:
                continue
            link = entry + offset
            log.debug(
                'got a element of list at %s 0x%x/0x%x offset:%d',
                fieldname, entry, link, offset)
            # use cache if possible, avoid loops.
            ref = self._memory_handler.getRef(structType, link)
            if ref:  # struct has already been loaded, bail out
                log.debug(
                    "%s loading from references cache %s/0x%lx",
                    fieldname, structType, link)
                continue  # do not reload
            else:
                # OFFSET read, specific to a LIST ENTRY model
                memoryMap = self._memory_handler.is_valid_address_value(link, structType)
                if memoryMap is False:
                    log.error('error while validating address 0x%x type:%s @end:0x%x', link,
                                                                                         structType.__name__, link + ctypes.sizeof(structType))
                    log.error(
                        'self : %s , fieldname : %s',
                        record.__class__.__name__, fieldname)
                    raise ValueError('error while validating address 0x%x type:%s @end:0x%x', link,
                                                                                                structType.__name__, link + ctypes.sizeof(structType))
                st = memoryMap.read_struct(
                    link,
                    structType)  # point at the right offset
                st._orig_address_ = link
                self._memory_handler.keepRef(st, structType, link)
                log.debug("keepRef %s.%s @%x", structType, fieldname, link)
                # load the list entry structure members
                if not self.load_members(st, max_depth - 1):
                    log.error(
                        'Error while loading members on %s',
                        record.__class__.__name__)
                    # print st
                    raise ValueError('error while loading members')

        return True

    def _is_loadable_member_list(self, attr, attrname, attrtype):
        """
            Check if the member is loadable.
            A c_void_p cannot be load generically, You have to take care of that.
        """
        if not super(ListModel, self)._is_loadable_member_list(
                attr, attrname, attrtype):
            return False
        if attrname in self._listMember_:
            log.debug(
                'load_members do NOT load %s, its a list element',
                attrname)
            return False
        # if attrname in [ name for name,t,f,o in self._listHead_]:
        ##    log.debug('load_members do NOT load %s, its a list HEAD element'%(attrname))
        # return False
        return True

    def load_members(self, record, max_depth):
        """
        load basic types members,
        then load list elements members recursively,
        then load list head elements members recursively.
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')

        log.debug(
            '-+ <%s> load_members +- @%x',
            record.__class__.__name__, record._orig_address_)

        #log.debug('load list elements at 0x%x'%(ctypes.addressof(self)))
        # call basicmodel
        if not super(ListModel, self).load_members(record, max_depth):
            return False

        log.debug(
            'load list elements members recursively on %s @%x ',
            type(record).__name__, record._orig_address_)
        log.debug('listmember %s' % record.__class__._listMember_)
        for fieldname in self._listMember_:
            self._load_list_entries(record, fieldname, max_depth - 1)

        log.debug(
            'load list head elements members recursively on %s',
            type(record).__name__)
        for fieldname, structType, structFieldname, offset in self.get_list_heads(type(record)):
            self._load_list_entries(record, fieldname, max_depth - 1)

        log.debug('-+ <%s> load_members END +-', record.__class__.__name__)
        return True

    def iterate_list_field(self, record, fieldname, sentinels=None):
        """
        start from the field    and iterate a list.
        does not return self.
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        if sentinels is None:
            sentinels = []
        structType, offset = self._getListFieldInfo(fieldname)

        # @ of the field
        headAddr = record._orig_address_ + self._utils.offsetof(type(record), fieldname)
        #log.info('Ignore headAddress self.%s at 0x%0.8x'%(fieldname, headAddr))
        head = getattr(record, fieldname)

        if not hasattr(head, '_iterateList'):
            raise ValueError(
                'Not an iterable field. Probably not declared as a list.')

        done = [s for s in sentinels] + [headAddr]
        for entry in self._iterate_list(head):
            # DO NOT think HEAD is a valid entry - FIXME
            if entry in done:
                continue
            # save it
            done.append(entry)
            # @ of the struct, entry is not null, head._iterateList garantizes it.
            link = entry + offset
            #log.info('Read %s at 0x%0.8x instead of 0x%0.8x'%(fieldname, link, entry))
            # use cache if possible, avoid loops.
            st = self._memory_handler.getRef(structType, link)
            #st._orig_address_ = link
            if st:
                yield st
            else:
                raise ValueError(
                    'the structure has not been loaded, please use load_members.')

        raise StopIteration

    def _get_list_field_info(self, record, fieldname):
        """
        if fieldname is in listmember, return offset of fieldname.
        if fieldname is in listhead, return offset of target field.
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        if fieldname in self._listMember_:
            return type(record), self._utils.offsetof(type(record), fieldname)
        for fname, typ, typFieldname, offset in self.get_list_heads(type(record)):
            if fieldname == fname:
                # FIXME: offset is also == utils.offsetof( typ, typFieldname)
                return typ, offset
        raise TypeError('This field %s is not a list.', fieldname)

    # def getListFieldIterator(self):
    #    """ returns [(fieldname, iterator), .. ] """
    #    for fieldname in self._listMember_:
    #        yield (fieldname, self.getFieldIterator(_memory_handler, fieldname ) )


    def iterate_list(self, record):
        """ iterate forward, then backward, until null or duplicate """
        done = [0]
        obj = record
        # print 'going forward '
        for fieldname in [forward, backward]:
            link = getattr(obj, fieldname)
            addr = self._utils.get_pointee_address(link)
            # print fieldname,addr,hex(addr)
            log.debug(
                'iterateList got a <%s>/0x%x',
                link.__class__.__name__, addr)
            nb = 0
            while addr not in done:
                # print '%x %s'%(addr, addr in done)
                done.append(addr)
                memoryMap = self._memory_handler.is_valid_address_value(addr, record_type)
                if memoryMap == False:
                    log.error(
                        "ValueError: 'the link of this linked list has a bad value'")
                    raise StopIteration
                st = memoryMap.read_struct(addr, record_type)
                st._orig_address_ = addr
                self._memory_handler.keepRef(st, record_type, addr)
                log.debug(
                    "keepRefx2 %s.%s: @%x",
                    record_type.__name__, fieldname, addr)
                yield addr
                # next
                link = getattr(st, fieldname)
                addr = self._utils.get_pointee_address(link)
            # print 'going backward after %x'%(addr)
        raise StopIteration

'''
        def load_members(self, record, depth):
            # voluntary blockade of load_members.
            # we do not want to validate members or pointees of this struct.
            log.debug('- <%s> load_members return TRUE', record_type.__name__)
            return True

        def attr_to_PyObject(self, attr, field, attrtype):
            if field in [forward, backward]:
                # TODO we could maybe put a pointer to parent struct ?
                # or add a hidden field in list struct representation so that the
                # python user can get the parent python object easily.
                return '# double_linked_list_type - contents not loaded'
            else:
                return self._attrToPyObject2(attr, field, attrtype)

        # set iterator on the list structure
        record_type._iterateList = iterate_list
        # structType.load_members = load_members # FIXME DEBUG WHY?
        # be nicer on printouts
        #structType._attrToPyObject2 = structType._attrToPyObject
        #structType._attrToPyObject = attr_to_PyObject

        log.debug(
            '%s has been fitted with a list iterator self._iterateList(_memory_handler)',
            record_type)
        return
'''