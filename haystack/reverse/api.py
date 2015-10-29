# -*- coding: utf-8 -*-

import logging

from haystack.abc import interfaces
from haystack.reverse import context
from haystack.reverse.heuristics import reversers
from haystack.reverse.heuristics import dsa
from haystack.reverse.heuristics import pointertypes

log = logging.getLogger('reverse.api')


def save_process_headers(memory_handler):
    """
        Save the python class code definition to file.

    :param memory_handler:
    :return:
    """
    process_context = memory_handler.get_reverse_context()
    log.info('[+] saving headers for process')
    fout = open(process_context.get_filename_cache_headers(), 'w')
    towrite = []
    #
    for r_type in process_context.list_reversed_types():
        members = process_context.get_reversed_type(r_type)
        from haystack.reverse.heuristics import constraints
        rev = constraints.ConstraintsReverser(memory_handler)
        txt = rev.verify(r_type, members)
        towrite.extend(txt)
        towrite.append("# %d members" % len(members))
        towrite.append(r_type.to_string())
        if len(towrite) >= 10000:
            try:
                fout.write('\n'.join(towrite))
            except UnicodeDecodeError as e:
                print 'ERROR on ', r_type
            towrite = []
            fout.flush()
    fout.write('\n'.join(towrite))
    fout.close()
    return


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
    ctx = context.get_context_for_address(memory_handler, heap_addr)
    try:
        # decode bytes contents to find basic types.
        log.info('Reversing Fields')
        fr = dsa.FieldReverser(memory_handler)
        fr.reverse_context(ctx)

        log.info('Fixing Text Fields')
        tfc = dsa.TextFieldCorrection(memory_handler)
        tfc.reverse_context(ctx)

        # try to find some logical constructs.
        log.info('Reversing DoubleLinkedListReverser')
        # why is this a reverse_context ?
        doublelink = reversers.DoubleLinkedListReverser(memory_handler)
        doublelink.reverse_context(ctx)
        doublelink.rename_all_lists()

        # save to file
        save_headers(ctx)

        # etc
    except KeyboardInterrupt as e:
        # except IOError,e:
        log.warning(e)
        log.info('[+] %d structs extracted' % (ctx.get_record_count()))
        raise e
        pass
    pass
    return ctx


def reverse_instances(memory_handler):
    """
    Reverse all heaps in process from memory_handler

    :param memory_handler:
    :return:
    """
    assert isinstance(memory_handler, interfaces.IMemoryHandler)
    finder = memory_handler.get_heap_finder()
    heaps = finder.get_heap_mappings()
    for heap in heaps:
        heap_addr = heap.get_marked_heap_address()
        # reverse all fields in all records from that heap
        reverse_heap(memory_handler, heap_addr)

    # then and only then can we look at the PointerFields
    # identify pointer relation between allocators
    log.info('Reversing PointerFields')
    pfr = pointertypes.PointerFieldReverser(memory_handler)
    pfr.reverse()

    # TODO save process type record

    # save that
    for heap in heaps:
        ctx = memory_handler.get_reverse_context().get_context_for_heap(heap)
        ctx.save_structures()
        # save to file
        save_headers(ctx)

    save_process_headers(memory_handler)

    # and then
    # graph pointer relations between allocators
    log.info('Reversing PointerGraph')
    ptrgraph = reversers.PointerGraphReverser(memory_handler)
    ptrgraph.reverse()

    # todo save graph method
    return


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
    # TODO check graph has been generated
    process_context = memory_handler.get_reverse_context()
    _records = process_context.get_predecessors(record)
    return _records
