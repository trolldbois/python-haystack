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
    Helpers to support records with double linked list members.

    """
    _listMember_ = []  # members that are the 2xpointer of same type linl
    #_listHead_ = []  # head structure of a linkedlist

    # double linked list management structure register
    _double_link_list_types = dict()
    # register for record/field part of a linked list
    _list_fields = dict()

    def register_double_linked_list_record_type(self, record_type, forward, backward):
        """
        Declares a structure to be a double linked list management structure.

        register_double_linked_list_record_type(struct_Entry, 'next', 'previous')

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

          register_double_linked_list_field_and_type(struct_type, field_name, list_entry_type, list_entry_field_name, offset)

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
        d = dict(basicmodel.get_record_type_fields(record_type))
        flink_type = d[forward]
        blink_type = d[backward]
        if not self._ctypes.is_pointer_type(flink_type):
            raise TypeError('The %s field is not a pointer.', forward)
        if not self._ctypes.is_pointer_type(blink_type):
            raise TypeError('The %s field is not a pointer.', backward)
        # ok - save that structure information
        self._double_link_list_types[record_type] = (forward, backward)
        return

    def is_double_linked_list_type(self, record_type):
        return record_type in self._double_link_list_types

    def get_double_linked_list_type(self, record_type):
        """
        return the registered double linked list information.
        :param record_type:
        :return: (forward, backward) fieldnames
        """
        return self._double_link_list_types[record_type]

    def register_double_linked_list_field_and_type(self, record_type, field_name, list_entry_type, list_entry_field_name):
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
            register_double_linked_list_record_type(struct_Entry, 'next', 'previous')
            register_double_linked_list_field_and_type(struct_Node, 'list', struct_Node, 'list')

        In the case of a list of child elements with siblings:
            register_double_linked_list_record_type(struct_Entry, 'next', 'previous')
            register_double_linked_list_field_and_type(struct_Node, 'list', struct_Child, 'siblings')
            register_double_linked_list_field_and_type(struct_Child, 'siblings', struct_Child, 'siblings')

        :param record_type: a ctypes record type
        :param field_name:
        :param list_entry_type:
        :param list_entry_field_name:
        :return:
        """
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a ctypes record type in record_type')
        if not issubclass(list_entry_type, ctypes.Structure) and not issubclass(list_entry_type, ctypes.Union):
            raise TypeError('Feed me a ctypes record type in list_entry_type')
        #
        if record_type not in self._list_fields:
            self._list_fields[record_type] = dict()
        # care offset is now positive
        offset = self._utils.offsetof(record_type, list_entry_field_name)
        self._list_fields[record_type][field_name] = (list_entry_type, list_entry_field_name, offset)

    # FIXME, the basicmodel name is _is_loadable_member
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

    def get_list_fields(self, record_type):
        """
        return the field in record_type that are part of a linked list.

        :param record_type:
        :return: [] if record_type has no registered field that is part of a linked list.
            [(field_name, list_entry_type, list_entry_field_name, offset)]
        """
        if isinstance(record_type, ctypes.Structure) or isinstance(record_type, ctypes.Union):
            raise TypeError('Feed me a type not an instance')
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a record type')
        mro = list(record_type.__mro__[:-3]) # cut Structure, _CData and object
        mro.reverse()
        me = mro.pop(-1)
        ret = []
        for typ in mro:  # firsts are first, cls is in here in [-1]
            if typ not in self._list_fields:
                continue
            for field_name, entries in self._list_fields[typ].items():
                ret.append((field_name, entries[0], entries[1], entries[2]))
        return ret

    def load_members(self, record, max_depth):
        """
        load basic types members,
        then load list elements members recursively,
        then load list head elements members recursively.

        :param record:
        :param max_depth:
        :return:
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        log.debug('-+ <%s> ListModel load_members +- @%x',record.__class__.__name__, record._orig_address_)
        if not super(ListModel, self).load_members(record, max_depth):
            return False
        # now try to load the list members
        log.debug('load list elements members recursively on %s @%x ',type(record).__name__, record._orig_address_)

        if self.is_double_linked_list_type(type(record)):
            # we cannot devine what the element of the list are gonna be.
            return True

        # we look at the list we know about
        for link_info in self.get_list_fields(type(record)):
            log.debug('checking listmember %s for %s', link_info[0], record.__class__.__name__)
            entry_iterator = self.iterate_list_from_field(record, link_info, sentinels=None)
            self._load_list_entries(record, entry_iterator, max_depth - 1)

        log.debug('-+ <%s> load_members END +-', record.__class__.__name__)
        return True

    def iterate_list_from_field(self, record, link_info, sentinels=None):
        """
         iterates over all entry of a double linked list.
         we do not return record in the list.

        :param record:
        :param link_info:
        :param sentinels:
        :return:
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        if sentinels is None:
            sentinels = []
        fieldname, pointee_record_type, lefn, offset = link_info
        # get the double linked list field name
        head = getattr(record, fieldname)
        # and its record_type
        field_record_type = type(head)
        # check that forward and backwards link field name were registered
        if not self.is_double_linked_list_type(field_record_type):
            raise RuntimeError("Field %s was defined as double link entry record type %s, but not registered" % (
                                fieldname,
                                field_record_type))
        # now that this is cleared, lets iterate.
        # @ of the fieldname in record. This can be different from offset.
        head_address = record._orig_address_ + self._utils.offsetof(type(record), fieldname)
        # stop at the first sign of a previously found list entry
        done = [s for s in sentinels] + [head_address]
        # log.info('Ignore headAddress self.%s at 0x%0.8x'%(fieldname, headAddr))
        # we get all addresses for the instances of the double linked list record_type
        # not, the list_member itself. Only the address of the double linked list field.
        for entry in self.iterate_list(head):
            # entry is not null. We also ignore record (head_address).
            if entry in done:
                continue
            # save it
            done.append(entry)
            # @ of the list member record
            list_member_address = entry - offset
            # log.info('Read %s at 0x%0.8x instead of 0x%0.8x'%(fieldname, link, entry))
            # use cache if possible, avoid loops.
            st = self._memory_handler.getRef(pointee_record_type, list_member_address)
            # st._orig_address_ = link
            if st:
                # we return
                yield st
            else:
                raise ValueError(
                    'the structure has not been loaded, please use load_members.')

        raise StopIteration

    def iterate_list(self, record):
        """
        iterate forward, then backward, until null or duplicate

        :param record:
        :return:
        """
        # stop when Null
        done = [0]
        obj = record
        record_type = type(record)
        forward, backward = self.get_double_linked_list_type(record_type)
        # log.debug('going forward ')
        for fieldname in [forward, backward]:
            link = getattr(obj, fieldname)
            addr = self._utils.get_pointee_address(link)
            log.debug('iterateList got a <%s>/0x%x', link.__class__.__name__, addr)
            nb = 0
            while addr not in done:
                done.append(addr)
                memoryMap = self._memory_handler.is_valid_address_value(addr, record_type)
                if memoryMap == False:
                    log.error("ValueError: 'the link of this linked list has a bad value'")
                    raise StopIteration
                st = memoryMap.read_struct(addr, record_type)
                st._orig_address_ = addr
                self._memory_handler.keepRef(st, record_type, addr)
                log.debug("keepRefx2 %s.%s: @%x", record_type.__name__, fieldname, addr)
                yield addr
                # next
                link = getattr(st, fieldname)
                addr = self._utils.get_pointee_address(link)
            # log.debug('going backward after %x', addr)
        raise StopIteration

    def _load_list_entries(self, record, link_iterator, max_depth):
        """
        for the link_info, we list max_depth element of the linked list.
        For each entry, we try to load the record using the constraint model.
        We keep cache in the memory_handler as to only evaluate every instance once.

        we need to load the pointed entry as a valid struct at the right offset,
        and parse it.

        When does it stop following FLink/BLink ?
            sentinel is headAddr only

        :param record:
        :param link_info:
        :param max_depth:
        :return:
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        fieldname, pointee_record_type, lefn, offset = link_info
        # DO NOT think HEAD is a valid entry.
        # if its a ListEntries, self has already been loaded anyway.
        # pointers are pointing to where ? start of structure or pointer itself ?
        headAddr = record._orig_address_ + self._utils.offsetof(type(record), fieldname)
        head = getattr(record, fieldname)

        for entry in self.iterate_list(head):
            # DO NOT think HEAD is a valid entry
            if entry == headAddr:
                continue
            link = entry + offset
            log.debug(
                'got a element of list at %s 0x%x/0x%x offset:%d',
                fieldname, entry, link, offset)
            # use cache if possible, avoid loops.
            ref = self._memory_handler.getRef(pointee_record_type, link)
            if ref:  # struct has already been loaded, bail out
                log.debug(
                    "%s loading from references cache %s/0x%lx",
                    fieldname, pointee_record_type, link)
                continue  # do not reload
            else:
                # OFFSET read, specific to a LIST ENTRY model
                memoryMap = self._memory_handler.is_valid_address_value(link, pointee_record_type)
                if memoryMap is False:
                    log.error('error while validating address 0x%x type:%s @end:0x%x', link,
                                                                                         pointee_record_type.__name__, link + ctypes.sizeof(pointee_record_type))
                    log.error(
                        'self : %s , fieldname : %s',
                        record.__class__.__name__, fieldname)
                    raise ValueError('error while validating address 0x%x type:%s @end:0x%x', link,
                                                                                                pointee_record_type.__name__, link + ctypes.sizeof(pointee_record_type))
                st = memoryMap.read_struct(
                    link,
                    pointee_record_type)  # point at the right offset
                st._orig_address_ = link
                self._memory_handler.keepRef(st, pointee_record_type, link)
                log.debug("keepRef %s.%s @%x", pointee_record_type, fieldname, link)
                # load the list entry structure members
                if not self.load_members(st, max_depth - 1):
                    log.error(
                        'Error while loading members on %s',
                        record.__class__.__name__)
                    # print st
                    raise ValueError('error while loading members')

        return True



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