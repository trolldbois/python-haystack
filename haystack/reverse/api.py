# -*- coding: utf-8 -*-

import logging

from haystack.abc import interfaces
from haystack.reverse import config
from haystack.reverse import context
from haystack.reverse.heuristics import reversers
from haystack.reverse.heuristics import dsa
from haystack.reverse.heuristics import pointertypes

log = logging.getLogger('reverse.api')


def save_headers(heap_context, addrs=None):
    """
    Save the python class code definition to file.

    :param heap_context:
    :param addrs:
    :return:
    """
    # structs_addrs is sorted
    log.info('[+] saving headers')
    fout = open(heap_context.get_filename_cache_headers(), 'w')
    towrite = []
    if addrs is None:
        addrs = iter(heap_context.listStructuresAddresses())
    #
    for vaddr in addrs:
        # anon = context._get_structures()[vaddr]
        anon = heap_context.get_record_for_address(vaddr)
        towrite.append(anon.to_string())
        if len(towrite) >= 10000:
            try:
                fout.write('\n'.join(towrite))
            except UnicodeDecodeError as e:
                print 'ERROR on ', anon
            towrite = []
            fout.flush()
    fout.write('\n'.join(towrite))
    fout.close()
    return


def reverse_heap(memory_handler, heap_addr):
    """
    Reverse a specific heap.

    :param memory_handler:
    :param heap_addr:
    :return:
    """
    from haystack.reverse import context
    log.info('[+] Loading the memory dump for HEAP 0x%x', heap_addr)
    heap_context = context.get_context_for_address(memory_handler, heap_addr)
    try:
        # decode bytes contents to find basic types.
        log.info('Reversing Fields')
        fr = dsa.FieldReverser(memory_handler)
        fr.reverse_context(heap_context)

        log.info('Fixing Text Fields')
        tfc = dsa.TextFieldCorrection(memory_handler)
        tfc.reverse_context(heap_context)

        # try to find some logical constructs.
        log.info('Reversing DoubleLinkedListReverser')
        # why is this a reverse_context ?
        doublelink = reversers.DoubleLinkedListReverser(memory_handler)
        doublelink.reverse_context(heap_context)
        doublelink.rename_all_lists()

        # save to file
        save_headers(heap_context)

        # etc
    except KeyboardInterrupt as e:
        # except IOError,e:
        log.warning(e)
        log.info('[+] %d structs extracted' % (heap_context.get_record_count()))
        raise e
        pass
    pass
    return heap_context


def reverse_instances(memory_handler):
    """
    Reverse all heaps in process from memory_handler

    :param memory_handler:
    :return:
    """
    assert isinstance(memory_handler, interfaces.IMemoryHandler)
    process_context = memory_handler.get_reverse_context()
    #for heap in heaps:
    #    # reverse all fields in all records from that heap
    #    ## reverse_heap(memory_handler, heap_addr)

    log.info('Reversing Fields')
    fr = dsa.FieldReverser(memory_handler)
    fr.reverse()

    log.info('Fixing Text Fields')
    tfc = dsa.TextFieldCorrection(memory_handler)
    tfc.reverse()

    # try to find some logical constructs.
    log.info('Reversing DoubleLinkedListReverser')
    # why is this a reverse_context ?
    doublelink = reversers.DoubleLinkedListReverser(memory_handler)
    doublelink.reverse()
    doublelink.rename_all_lists()

    # then and only then can we look at the PointerFields
    # identify pointer relation between allocators
    log.info('Reversing PointerFields')
    pfr = pointertypes.PointerFieldReverser(memory_handler)
    pfr.reverse()

    # save that
    log.info('Saving reversed records instances')
    for heap_context in process_context.list_contextes():
        heap_context.save_structures()
        # save to file
        save_headers(heap_context)

    log.info('Saving reversed records types')
    process_context.save_reversed_types()

    # graph pointer relations between allocators
    log.info('Reversing PointerGraph')
    ptrgraph = reversers.PointerGraphReverser(memory_handler)
    ptrgraph.reverse()

    # extract all strings
    log.info('Reversing strings')
    strout = reversers.StringsReverser(memory_handler)
    strout.reverse()

    log.info('Analysis results are in %s', config.get_cache_folder_name(memory_handler.get_name()))
    return process_context


def get_record_at_address(memory_handler, record_address):
    """
    Returns the record athe specified address.

    :param memory_handler:
    :param record_address:
    :return:
    """
    heap_context = context.get_context_for_address(memory_handler, record_address)
    return heap_context.get_record_at_address(record_address)


def get_record_predecessors(memory_handler, record):
    """
    Returns the predecessors of this record.

    :param memory_handler:
    :param record:
    :return:
    """
    process_context = memory_handler.get_reverse_context()
    _records = process_context.get_predecessors(record)
    return _records
