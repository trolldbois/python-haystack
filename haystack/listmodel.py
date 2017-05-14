# -*- coding: utf-8 -*-
#
from __future__ import print_function

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
listmodel usage:

C code example:
    /* For single pointer lists */
    struct SListEntry {
        struct SListEntry * next;
    }
    struct Items {
        int hi;
        struct SListEntry list_of_items;
    }
    struct SubItems {
        int hi;
        struct SListEntry siblings;
    }
    struct Items2 {
        int hi;
        struct SListEntry list_of_items;
        int ho;
    }

    /* For double linked lists */
    struct DoubleListEntry {
        struct DoubleListEntry * next;
        struct DoubleListEntry * previous;
    }
    struct Node {
        int hi;
        struct DoubleListEntry list_of_nodes;
    }
    struct Root {
        int hi;
        struct DoubleListEntry children;
    }
    struct Child {
        float c;
        struct DoubleListEntry siblings_child;
    }

Registration usage:
In case of a single link list of siblings:
    register_single_linked_list_record_type(struct_SListEntry, 'next')
    register_linked_list_field_and_type(struct_Items, 'list_of_items', struct_Items, 'list_of_items')
    register_linked_list_field_and_type(struct_Items2, 'list_of_items', struct_Items2, 'list_of_items')

In case of a single link list:
    register_single_linked_list_record_type(struct_SListEntry, 'next')
    register_linked_list_field_and_type(struct_Items, 'list_of_items', struct_SubItems, 'siblings')
    register_linked_list_field_and_type(struct_SubItems, 'siblings', struct_SubItems, 'siblings')

In the case of a double linked list of siblings:
    register_double_linked_list_record_type(struct_DoubleListEntry, 'next', 'previous')
    register_linked_list_field_and_type(struct_Node, 'list_of_nodes', struct_DoubleListEntry, 'list_of_nodes')

In the case of a double linked list of child elements with siblings:
    register_double_linked_list_record_type(struct_DoubleListEntry, 'next', 'previous')
    register_linked_list_field_and_type(struct_Root, 'children', struct_Child, 'siblings')
    register_linked_list_field_and_type(struct_Child, 'siblings', struct_Child, 'siblings')

In code usage:
use
    _iterate_list_from_field_with_link_info(record, fieldname, sentinel_values)
to iterate on elements of the list.


"""

import ctypes
import logging

from haystack import basicmodel
from haystack import constraints

log = logging.getLogger('listmodel')


class ListModel(basicmodel.CTypesRecordConstraintValidator):
    """
    Helpers to support records with double linked list members.

    """
    # single linked list management structure register
    _single_link_list_types = dict()
    # double linked list management structure register
    _double_link_list_types = dict()
    # register for record/field part of a linked list
    _list_fields = dict()

    def is_single_linked_list_type(self, record_type):
        return record_type in self._single_link_list_types

    def is_double_linked_list_type(self, record_type):
        return record_type in self._double_link_list_types

    def get_single_linked_list_type(self, record_type):
        """
        return the registered single linked list information.
        :param record_type:
        :return: (forward, sentinels) fieldnames
        """
        return self._single_link_list_types[record_type]

    def get_double_linked_list_type(self, record_type):
        """
        return the registered double linked list information.
        :param record_type:
        :return: (forward, backward, sentinels) fieldnames
        """
        return self._double_link_list_types[record_type]

    def register_single_linked_list_record_type(self, record_type, forward, sentinels=None):
        """
        Declares a structure to be a single linked list management structure.

        register_single_linked_list_record_type(struct_SListEntry, 'forward')

        C code example:
            struct SListEntry {
                struct SListEntry * next;
            }

        Impacts:
        The effect will be the structure type's instance will NOT be validated, or loaded
        by the ListModel Constraints validator.
        No member, pointers members will be loaded.
        But elements of the list can be iterated upon with ListModel._iterate_double_linked_list,
        At what point, address validation of both forward and backward pointer
        occurs before loading of pointee elements.

        :param record_type: the ctypes.Structure type that holds double linked list pointers fields
        :param forward: the list pointer fieldname
        :return: None
        """
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a ctypes record rype')
        # test field existences in instance
        flink_type = getattr(record_type, forward)
        # test field existences in type
        d = dict(basicmodel.get_record_type_fields(record_type))
        flink_type = d[forward]
        if not self._ctypes.is_pointer_type(flink_type):
            raise TypeError('The %s field is not a pointer.', forward)
        if sentinels is None:
            sentinels = {0} # Null pointer
        # ok - save that structure information
        self._single_link_list_types[record_type] = (forward, sentinels)
        return

    def register_double_linked_list_record_type(self, record_type, forward, backward, sentinels=None):
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

          register_linked_list_field_and_type(struct_type, field_name, list_entry_type, list_entry_field_name, offset)

        Impacts:
        The effect will be the structure type's instance will NOT be validated, or loaded
        by the ListModel Constraints validator.
        No member, pointers members will be loaded.
        But elements of the list can be iterated upon with ListModel._iterate_double_linked_list,
        At what point, address validation of both forward and backward pointer
        occurs before loading of pointee elements.

        :param record_type: the ctypes.Structure type that holds double linked list pointers fields
        :param forward: the forward pointer
        :param backward: the backward pointer
        :return: None
        """
        if not issubclass(record_type, ctypes.Structure) and not issubclass(record_type, ctypes.Union):
            raise TypeError('Feed me a ctypes record rype')
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
        if sentinels is None:
            sentinels = {0} # Null pointer
        # ok - save that structure information
        self._double_link_list_types[record_type] = (forward, backward, sentinels)
        return

    def register_linked_list_field_and_type(self, record_type, field_name, list_entry_type, list_entry_field_name):
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
            register_linked_list_field_and_type(struct_Node, 'list', struct_Node, 'list')

        In the case of a list of child elements with siblings:
            register_double_linked_list_record_type(struct_Entry, 'next', 'previous')
            register_linked_list_field_and_type(struct_Node, 'list', struct_Child, 'siblings')
            register_linked_list_field_and_type(struct_Child, 'siblings', struct_Child, 'siblings')

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
        offset = self._utils.offsetof(list_entry_type, list_entry_field_name)
        self._list_fields[record_type][field_name] = (list_entry_type, list_entry_field_name, offset)
        return

    def _get_list_info_for_field_for(self, record_type, fieldname):
        """
        Returns the list info for a field in a record_type.
        :param record_type:
        :param fieldname:
        :return:
        """
        for x in self._get_list_fields(record_type):
            if x[0] == fieldname:
                return x
        raise ValueError('No such registered list field: %s for type: %s' % (fieldname, record_type.__name__))

    def _get_list_fields(self, record_type):
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
        # FIXME, ctypes.Structure should not be modified
        mro = list(record_type.__mro__[:-3]) # cut Structure, _CData and object
        mro.reverse()
        #me = mro.pop(-1)
        ret = []
        for typ in mro:  # firsts are first, cls is in here in [-1]
            if typ not in self._list_fields:
                continue
            for field_name, entries in self._list_fields[typ].items():
                ret.append((field_name, entries[0], entries[1], entries[2]))
        return ret

    def iterate_list_from_field(self, record, fieldname, sentinels=None, ignore_head=True):
        """
        Iterate over the items of the list designated by fieldname in record.
        :param record:
        :param fieldname:
        :param sentinels: values that stop the iteration
        :return:
        """
        link_info = self._get_list_info_for_field_for(type(record), fieldname)
        return self._iterate_list_from_field_with_link_info(record, link_info, sentinels, ignore_head)

    def iterate_list_from_pointer_field(self, pointer_field, target_fieldname, sentinels=None):
        """
        Iterate over the items of the list designated by fieldname (a pointer) in record.
        Do not ignore head, by default.

        :param record:
        :param fieldname:
        :param sentinels: values that stop the iteration
        :return:
        """
        if sentinels is None:
            sentinels = set()
        # instead of asking the pointer field to be registered,
        # we will look up directly the pointee type.
        # But them how would we know 'which' list to get ? -> target_fieldname in the pointee type.
        # the pointee type has to be a registered list record type. Not a parent record
        # therefore, the list is obvious.
        field_record_type = type(pointer_field)
        # if the field is a pointer, assume that the root of the list is the pointee
        if not self._ctypes.is_pointer_type(field_record_type):
            raise TypeError('Field should be a pointer')
        pointee_type = self._ctypes.get_pointee_type(field_record_type)
        if not self._ctypes.is_struct_type(pointee_type):
            raise TypeError('Field should be a pointer to a structure')
        if not self.is_single_linked_list_type(pointee_type) \
                and not self.is_double_linked_list_type(pointee_type)\
                and pointee_type not in self._list_fields:
            raise TypeError('Pointee type %s is not a registered list record type' % pointee_type)
        head_addr = self._utils.get_pointee_address(pointer_field)
        if head_addr == 0 or head_addr in sentinels:
            return []
        memory_map = self._memory_handler.is_valid_address_value(head_addr, pointee_type)
        if memory_map is False:
            log.error("_iterate_list_pointer_field: the root of this linked list has a bad value: 0x%x", head_addr)
            raise ValueError('ValueError: the root of this linked list has a bad value: 0x%x' % head_addr)
        head = memory_map.read_struct(head_addr, pointee_type)
        self._memory_handler.keepRef(head, pointee_type, head_addr)
        # you need to use target_fieldname in pointee_type, to know what is the list.
        # if type of target_fieldname is registered as a list type
        link_info = self._get_list_info_for_field_for(pointee_type, target_fieldname)
        return self._iterate_list_from_field_with_link_info(head, link_info, sentinels, ignore_head=False)

    def _iterate_list_from_field_with_link_info(self, record, link_info, sentinels=None, ignore_head=True):
        """
         iterates over all entry of a double linked list.
         we do not return record in the list.

        :param record:
        :param link_info:
        :param sentinels: values that stop the iteration
        :return:
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a ctypes record instance')
        if sentinels is None:
            sentinels = set()
        fieldname, pointee_record_type, lefn, offset = link_info
        # get the list field name
        head = getattr(record, fieldname)
        # and its record_type
        field_record_type = type(head)
        # handle pointer cases
        if self._ctypes.is_pointer_type(field_record_type):
            field_record_type = self._ctypes.get_pointee_type(field_record_type)
        # check that forward and backwards link field name were registered
        iterator_fn = None
        if self.is_single_linked_list_type(field_record_type):
            iterator_fn = self._iterate_single_linked_list
            # stop at the first sign of a previously found list entry
            _, gbl_sentinels = self.get_single_linked_list_type(field_record_type)
        elif self.is_double_linked_list_type(field_record_type):
            iterator_fn = self._iterate_double_linked_list
            # stop at the first sign of a previously found list entry
            _, _, gbl_sentinels = self.get_double_linked_list_type(field_record_type)
        else:
            import traceback
            print(traceback.print_stack())
            raise RuntimeError("Field %s was defined as linked link entry record type %s, but not registered" % (
                                fieldname, field_record_type))
        # now that this is cleared, lets iterate.
        if not ignore_head:
            # in case of ENTRY x2 list, head is ENTRY.
            log.debug('Yield head because NOT Ignoring head in inner')
            yield record
        # @ of the fieldname in record. This can be different from offset.
        head_address = record._orig_address_ + self._utils.offsetof(type(record), fieldname)
        head._orig_address_ = head_address
        # stop at the first sign of a previously found list entry
        if ignore_head:
            done = sentinels | gbl_sentinels | {head_address}
            log.debug('Ignore head_address self.%s at 0x%0.8x' % (fieldname, head_address))
        else:
            done = sentinels | gbl_sentinels
            log.debug('NOT Ignoring head_address self.%s at 0x%0.8x' % (fieldname, head_address))
            # TODO, TU that.
        #
        log.debug("_iterate_list_from_field_with_link_info Field:%s at offset:%d st_size:%d", fieldname, offset, self._ctypes.sizeof(pointee_record_type))
        for x in self._iterate_list_from_field_inner(iterator_fn, head, pointee_record_type, offset, done):
            yield x
        raise StopIteration

    def _iterate_list_from_field_inner(self, iterator_fn, head, pointee_record_type, offset, sentinels):
        """
        Use iterator_fn to iterate on the list allocators. (as in struct__LIST_ENTRY)
        For each list entry address:
            + verify if the entry address is a sentinel value or already parsed.
            + calculate <list_entry_address> - offset to find the real list entry address
            + check if its in cache and yield it
            + otherwise, if its a valid address, read the record from the new address
            + save it to cache
            + yield it.

        :param iterator_fn: an iterator on a registered list entry management structure
        :param head: the first list entry
        :param pointee_record_type: the list entry record type we want to load
        :param offset: the offset between the list entry pointers and the interesting record
        :param sentinels: values that indicates we should stop iterating.
        :return: pointee_record_type()
        """
        # we get all addresses for the instances of the double linked list record_type
        # not, the list_member itself. Only the address of the double linked list field.
        for entry in iterator_fn(head, sentinels):
            # @ of the list member record
            list_member_address = entry - offset
            log.debug('iterate on entry 0x%x, offset 0x%x res: 0x%x', entry, offset, list_member_address)
            # entry is not null. We also ignore record (head_address).
            if entry in sentinels:
                log.debug('entry 0x%x in sentinel, skipping', entry)
                continue
            elif list_member_address in sentinels:
                log.debug('list_member_address 0x%x in sentinel, skipping', list_member_address)
                continue
            # use cache if possible, avoid loops.
            st = self._memory_handler.getRef(pointee_record_type, list_member_address)
            # st._orig_address_ = link
            if st is not None:
                # we return the cached value
                log.debug('_iterate_list_from_field_inner getRef returned cached value on 0x%x', list_member_address)
                yield st
            else:
                memoryMap = self._memory_handler.is_valid_address_value(list_member_address, pointee_record_type)
                if memoryMap == False:
                    type_size = self._ctypes.sizeof(pointee_record_type)
                    log.error('_iterate_list_from_field_inner: bad value link_addr: 0x%x size: 0x%x', list_member_address, type_size)
                    log.debug('sentinels: {%s}', ','.join(['0x%0.8x' % s for s in sentinels]))
                    log.debug('entry on sentinels: %s', entry in sentinels)
                    log.debug('list_member_address in sentinels: %s', list_member_address in sentinels)
                    raise ValueError('the link of this linked list has a bad value: 0x%x' % entry)
                st = memoryMap.read_struct(list_member_address, pointee_record_type)
                st._orig_address_ = list_member_address
                self._memory_handler.keepRef(st, pointee_record_type, list_member_address)
                yield st
            # save the last address as a sentinel
            sentinels.add(list_member_address)
        raise StopIteration

    def _iterate_double_linked_list(self, record, sentinels=None):
        """
        iterate forward, then backward, until null or duplicate

        :param record:
        :return:
        """
        # stop when Null
        done = {0}
        if sentinels is None:
            sentinels = {}
        obj = record
        record_type = type(record)
        # we ignore the sentinels here, as this is an internal iterator
        forward, backward, _ = self.get_double_linked_list_type(record_type)
        log.debug('sentinels: {%s}', ','.join(['0x%0.8x' % s for s in sentinels]))
        # make the stack
        stack = set()
        for fieldname in [forward, backward]:
            link = getattr(obj, fieldname)
            addr = self._utils.get_pointee_address(link)
            stack.add(addr)
        # go trough the tree
        while 1:
            new_nodes = set()
            if len(stack) == 0:
                log.debug('x2_list: empty stack, stop iteration')
                break
            for addr in stack:
                if addr in done or addr in sentinels:
                    log.debug('x2_list: addr: 0x%x in done or sentinels', addr)
                    continue
                done.add(addr)
                memory_map = self._memory_handler.is_valid_address_value(addr, record_type)
                if memory_map is False:
                    log.error("_iterate_double_linked_list: the link of this linked list has a bad value: 0x%x", addr)
                    raise ValueError('ValueError: the link of this linked list has a bad value: 0x%x' % addr)
                st = memory_map.read_struct(addr, record_type)
                st._orig_address_ = addr
                self._memory_handler.keepRef(st, record_type, addr)
                log.debug("keepRefx2 %s.%s: @%x", record_type.__name__, fieldname, addr)
                yield addr
                # next
                f_addr = self._utils.get_pointee_address(getattr(st, forward))
                b_addr = self._utils.get_pointee_address(getattr(st, backward))
                new_nodes.add(f_addr)
                new_nodes.add(b_addr)
                log.debug('_iterate_double_linked_list %s <%s>/0x%x', forward, link.__class__.__name__, f_addr)
                log.debug('_iterate_double_linked_list %s <%s>/0x%x', backward, link.__class__.__name__, b_addr)
            stack = new_nodes
        raise StopIteration

    def _iterate_single_linked_list(self, record, sentinels=None):
        """
        iterate forward, until null or duplicate

        :param record:
        :return:
        """
        # stop when Null
        done = {0}
        record_type = type(record)
        # handle pointer cases
        if self._ctypes.is_pointer_type(record_type):
            record_type = self._ctypes.get_pointee_type(record_type)
            # we ignore the sentinels here as this is an internal iterator
            fieldname, _ = self.get_single_linked_list_type(record_type)
            addr = self._utils.get_pointee_address(record)
            log.debug('_iterate_single_linked_list <%s>/0x%x', record_type.__name__, addr)
        else:
            # we ignore the sentinels here as this is an internal iterator
            fieldname, _ = self.get_single_linked_list_type(record_type)
            # log.debug("sentinels %s", str([hex(s) for s in sentinels]))
            link = getattr(record, fieldname)
            addr = self._utils.get_pointee_address(link)
            log.debug('_iterate_single_linked_list <%s>/0x%x', link.__class__.__name__, addr)
        nb = 0
        while addr not in done and addr not in sentinels:
            done.add(addr)
            _map = self._memory_handler.is_valid_address_value(addr, record_type)
            if not _map:
                log.error("_iterate_single_linked_list: the link of this linked list has a bad value")
                raise ValueError('ValueError: the link of this linked list has a bad value: 0x%x' % addr)
            st = _map.read_struct(addr, record_type)
            st._orig_address_ = addr
            self._memory_handler.keepRef(st, record_type, addr)
            log.debug("keepRefx2 %s.%s: @%x", record_type.__name__, fieldname, addr)
            yield addr
            # next
            link = getattr(st, fieldname)
            addr = self._utils.get_pointee_address(link)
            log.debug('_iterate_single_linked_list <%s>/0x%x', link.__class__.__name__, addr)
        raise StopIteration

    def is_valid(self, record):
        """
        Checks if each members has coherent data.
        If its a list record, check its list values for sentinels.
        """
        if not isinstance(record, ctypes.Structure) and not isinstance(record, ctypes.Union):
            raise TypeError('Feed me a record')
        # we check for sentinels
        sentinels = None
        if self.is_single_linked_list_type(type(record)):
            forward, sentinels = self.get_single_linked_list_type(type(record))
            fieldnames = [forward]
        elif self.is_double_linked_list_type(type(record)):
            forward, backward, sentinels = self.get_double_linked_list_type(type(record))
            fieldnames = [forward, backward]
        else:
            return super(ListModel, self).is_valid(record)
        # check if it is
        for fieldname in fieldnames:
            link = getattr(record, fieldname)
            addr = self._utils.get_pointee_address(link)
            if addr in sentinels:
                # FIXME: we are here ignoring the values of any other fields in record.
                return True
        # else transfer control to super
        return super(ListModel, self).is_valid(record)

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
        if max_depth <= 0:
            log.debug('Maximum depth reach. Not loading any deeper members.')
            log.debug('Struct partially LOADED. %s not loaded', record.__class__.__name__)
            return True
        if max_depth > 100:
            raise RuntimeError('max_depth')
        log.debug('-+ <%s> ListModel load_members +- @%x', record.__class__.__name__, record._orig_address_)
        if not super(ListModel, self).load_members(record, max_depth):
            log.debug('basicmodel returned False')
            return False
        # now try to load the list members
        log.debug('d:%d load list elements members recursively on %s @%x ', max_depth, type(record).__name__, record._orig_address_)

        if self.is_single_linked_list_type(type(record)):
            # we cannot devine what the element of the list are gonna be.
            return True
        elif self.is_double_linked_list_type(type(record)):
            # we cannot devine what the element of the list are gonna be.
            return True
        try:
            record_constraints = self._get_constraints_for(record)
            # we look at the list we know about
            for link_info in self._get_list_fields(type(record)):
                attrname = link_info[0]
                ignore = False
                # shorcut ignores
                if attrname in record_constraints:
                    for constraint in record_constraints[attrname]:
                        if constraint is constraints.IgnoreMember:
                            log.debug('ignoring %s as requested', attrname)
                            ignore = True
                            break
                        elif isinstance(constraint, constraints.ListLimitDepthValidation):
                            max_depth = constraint.max_depth
                            log.debug('setting max_depth %d as requested', max_depth)
                    continue
                if ignore:
                    continue
                log.debug('d:%d checking listmember %s for %s', max_depth, link_info[0], record.__class__.__name__)
                # FIXME: choose if its a pointer to list or a list member
                entry_iterator = self._iterate_list_from_field_with_link_info(record, link_info)
                self._load_list_entries(record, entry_iterator, max_depth - 1)
        except ValueError as e:
            log.debug(e)
            return False
        except RuntimeError as e: # for DEBUG
            log.debug(e)
            return False
        log.debug('-+ <%s> load_members END +-', record.__class__.__name__)
        return True

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

        for list_member in link_iterator:
            # load the list entry structure members
            log.debug('send %s to load_members' % list_member)
            if not self.load_members(list_member, max_depth - 1):
                log.error(
                    'Error while loading members on %s',
                    record.__class__.__name__)
                # print st
                raise ValueError('error while loading members')

        return True
