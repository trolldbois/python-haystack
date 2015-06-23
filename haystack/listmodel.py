#!/usr/bin/env python
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
from haystack import utils

import logging

log = logging.getLogger('listmodel')


class ListModel(object):

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
    _listHead_ = []  # head structure of a linkedlist

    def _loadListEntries(self, fieldname, mappings, maxDepth):
        """
        we need to load the pointed entry as a valid struct at the right offset,
        and parse it.

        When does it stop following FLink/BLink ?
            sentinel is headAddr only
        """
        import ctypes
        structType, offset = self._getListFieldInfo(fieldname)
        # FIXME offset == utils.offsetof(type(self), fieldname)
        # DO NOT think HEAD is a valid entry.
        # if its a ListEntries, self has already been loaded anyway.
        headAddr = self._orig_address_ + utils.offsetof(type(self), fieldname)
        head = getattr(self, fieldname)

        for entry in head._iterateList(mappings):
            # DO NOT think HEAD is a valid entry
            if entry == headAddr:
                continue
            link = entry + offset
            log.debug(
                'got a element of list at %s 0x%x/0x%x offset:%d' %
                (fieldname, entry, link, offset))
            # use cache if possible, avoid loops.
            ref = mappings.getRef(structType, link)
            if ref:  # struct has already been loaded, bail out
                log.debug(
                    "%s loading from references cache %s/0x%lx" %
                    (fieldname, structType, link))
                continue  # do not reload
            else:
                # OFFSET read, specific to a LIST ENTRY model
                memoryMap = mappings.is_valid_address_value(link, structType)
                if memoryMap is False:
                    log.error('error while validating address 0x%x type:%s @end:0x%x' % (link,
                                                                                         structType.__name__, link + ctypes.sizeof(structType)))
                    log.error(
                        'self : %s , fieldname : %s' %
                        (self.__class__.__name__, fieldname))
                    raise ValueError('error while validating address 0x%x type:%s @end:0x%x' % (link,
                                                                                                structType.__name__, link + ctypes.sizeof(structType)))
                st = memoryMap.readStruct(
                    link,
                    structType)  # point at the right offset
                st._orig_address_ = link
                mappings.keepRef(st, structType, link)
                log.debug("keepRef %s.%s @%x" % (structType, fieldname, link))
                # load the list entry structure members
                if not st.loadMembers(mappings, maxDepth - 1):
                    log.error(
                        'Error while loading members on %s' %
                        (self.__class__.__name__))
                    # print st
                    raise ValueError('error while loading members')

        return True

    def _isLoadableMemberList(self, attr, attrname, attrtype):
        """
            Check if the member is loadable.
            A c_void_p cannot be load generically, You have to take care of that.
        """
        if not super(ListModel, self)._isLoadableMemberList(
                attr, attrname, attrtype):
            return False
        if attrname in self._listMember_:
            log.debug(
                'loadMembers do NOT load %s, its a list element' %
                (attrname))
            return False
        # if attrname in [ name for name,t,f,o in self._listHead_]:
        ##    log.debug('loadMembers do NOT load %s, its a list HEAD element'%(attrname))
        # return False
        return True

    def loadMembers(self, mappings, maxDepth):
        """
        load basic types members,
        then load list elements members recursively,
        then load list head elements members recursively.
        """
        log.debug(
            '-+ <%s> loadMembers +- @%x' %
            (self.__class__.__name__, self._orig_address_))

        #log.debug('load list elements at 0x%x'%(ctypes.addressof(self)))
        # call basicmodel
        if not super(ListModel, self).loadMembers(mappings, maxDepth):
            return False

        log.debug(
            'load list elements members recursively on %s @%x ' %
            (type(self).__name__, self._orig_address_))
        log.debug('listmember %s' % self.__class__._listMember_)
        for fieldname in self._listMember_:
            self._loadListEntries(fieldname, mappings, maxDepth - 1)

        log.debug(
            'load list head elements members recursively on %s' %
            (type(self).__name__))
        for fieldname, structType, structFieldname, offset in self._listHead_:
            self._loadListEntries(fieldname, mappings, maxDepth - 1)

        log.debug('-+ <%s> loadMembers END +-' % (self.__class__.__name__))
        return True

    def iterateListField(self, mappings, fieldname, sentinels=[]):
        """
        start from the field    and iterate a list.
        does not return self."""

        structType, offset = self._getListFieldInfo(fieldname)

        # @ of the field
        headAddr = self._orig_address_ + utils.offsetof(type(self), fieldname)
        #log.info('Ignore headAddress self.%s at 0x%0.8x'%(fieldname, headAddr))
        head = getattr(self, fieldname)

        if not hasattr(head, '_iterateList'):
            raise ValueError(
                'Not an iterable field. Probably not declared as a list.')

        done = [s for s in sentinels] + [headAddr]
        for entry in head._iterateList(mappings):
            # DO NOT think HEAD is a valid entry - FIXME
            if entry in done:
                continue
            # save it
            done.append(entry)
            # @ of the struct, entry is not null, head._iterateList garantizes it.
            link = entry + offset
            #log.info('Read %s at 0x%0.8x instead of 0x%0.8x'%(fieldname, link, entry))
            # use cache if possible, avoid loops.
            st = mappings.getRef(structType, link)
            #st._orig_address_ = link
            if st:
                yield st
            else:
                raise ValueError(
                    'the structure has not been loaded, please use loadMembers.')

        raise StopIteration

    def _getListFieldInfo(self, fieldname):
        """
        if fieldname is in listmember, return offset of fieldname.
        if fieldname is in listhead, return offset of target field.
        """
        if fieldname in self._listMember_:
            return type(self), utils.offsetof(type(self), fieldname)
        for fname, typ, typFieldname, offset in self._listHead_:
            if fieldname == fname:
                # FIXME: offset is also == utils.offsetof( typ, typFieldname)
                return typ, offset
        raise TypeError('This field %s is not a list.' % (fieldname))

    # def getListFieldIterator(self):
    #    """ returns [(fieldname, iterator), .. ] """
    #    for fieldname in self._listMember_:
    #        yield (fieldname, self.getFieldIterator(mappings, fieldname ) )


def declare_double_linked_list_type(structType, forward, backward):
    """Declares a list iterator on structType, as used by ListModel.

    declare_double_linked_list_type(struct_A, 'next', 'previous')

    C code example:
    struct Entry {
        struct Entry * next;
        struct Entry * previous;
    }

    The effect will be the current structType will NOT be validated, or loaded
    by basicmodel. No member, pointers members will be loaded.
    But next and previous elements can be iterated upon with _iterateList,
    at what point, address validation of both forward and backward pointer
    occurs before loading of pointee.
    """
    import ctypes
    # test existence
    flinkType = getattr(structType, forward)
    blinkType = getattr(structType, backward)
    d = dict(structType.getFields())
    flinkType = d[forward]
    blinkType = d[backward]
    if not ctypes.is_pointer_type(flinkType):
        raise TypeError('The %s field is not a pointer.' % (forward))
    if not ctypes.is_pointer_type(blinkType):
        raise TypeError('The %s field is not a pointer.' % (backward))

    def iterateList(self, mappings):
        """ iterate forward, then backward, until null or duplicate """
        done = [0]
        obj = self
        # print 'going forward '
        for fieldname in [forward, backward]:
            link = getattr(obj, fieldname)
            addr = utils.get_pointee_address(link)
            # print fieldname,addr,hex(addr)
            log.debug(
                'iterateList got a <%s>/0x%x' %
                (link.__class__.__name__, addr))
            nb = 0
            while addr not in done:
                # print '%x %s'%(addr, addr in done)
                done.append(addr)
                memoryMap = mappings.is_valid_address_value(addr, structType)
                if memoryMap == False:
                    log.error(
                        "ValueError: 'the link of this linked list has a bad value'")
                    raise StopIteration
                st = memoryMap.readStruct(addr, structType)
                st._orig_address_ = addr
                mappings.keepRef(st, structType, addr)
                log.debug(
                    "keepRefx2 %s.%s: @%x" %
                    (structType.__name__, fieldname, addr))
                yield addr
                # next
                link = getattr(st, fieldname)
                addr = utils.get_pointee_address(link)
            # print 'going backward after %x'%(addr)
        raise StopIteration

    def loadMembers(self, mappings, depth):
        # voluntary blockade of loadMembers.
        # we do not want to validate members or pointees of this struct.
        log.debug('- <%s> loadMembers return TRUE' % (structType.__name__))
        return True

    def attrToPyObject(self, attr, field, attrtype):
        if field in [forward, backward]:
            # TODO we could maybe put a pointer to parent struct ?
            # or add a hidden field in list struct representation so that the
            # python user can get the parent python object easily.
            return '# double_linked_list_type - contents not loaded'
        else:
            return self._attrToPyObject2(attr, field, attrtype)

    # set iterator on the list structure
    structType._iterateList = iterateList
    # structType.loadMembers = loadMembers # FIXME DEBUG WHY?
    # be nicer on printouts
    #structType._attrToPyObject2 = structType._attrToPyObject
    #structType._attrToPyObject = attrToPyObject

    log.debug(
        '%s has been fitted with a list iterator self._iterateList(mappings)' %
        (structType))
    return
