#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Search for a known structure type in a process memory. """

import logging
import time

from haystack import basicmodel
from haystack import constraints
from haystack.search import api
from haystack.memory_mapper import MemoryHandlerFactory

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('abouchet')

class HaystackError(Exception):
    pass

def _get_memory_handler(args):
    if args.volname is not None:
        memory_handler = MemoryHandlerFactory(
            pid=args.pid,
            volname=args.volname).make_memory_handler()
    elif args.pid is not None:
        memory_handler = MemoryHandlerFactory(pid=args.pid, mmap=args.mmap).make_memory_handler()
    elif args.dumpname is not None:
        memory_handler = MemoryHandlerFactory(dumpname=args.dumpname).make_memory_handler()
    elif args.memfile is not None:
        memory_handler = MemoryHandlerFactory(
            memfile=args.memfile,
            baseOffset=args.baseOffset).make_memory_handler()
    else:
        log.error('Nor PID, not memfile, not dumpname. What do you expect ?')
        raise RuntimeError(
            'Please validate the argparser. I couldnt find any useful information in your args.')
    return memory_handler

def _get_output_style(args):
    rtype = None
    if args.human:
        rtype = 'string'
    elif args.json:
        rtype = 'json'
    elif args.pickled:
        rtype = 'pickled'
    return rtype

def search_cmdline(args):
    """ Internal cmdline mojo. """
    # get the memory handler adequate for the type requested
    memory_handler = _get_memory_handler(args)
    # print output on stdout
    rtype = _get_output_style(args)
    # try to load constraints
    # mapper
    if args.constraints_file:
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read(args.constraints_file.name)
    else:
        my_constraints = None
    # get the structure name
    modulename, sep, classname = args.struct_name.rpartition('.')
    module = memory_handler.get_model().import_module(modulename)
    struct_type = getattr(module, classname)
    # do the search
    results = api.search_record(memory_handler, struct_type, my_constraints, extended_search=args.extended_search)
    if args.interactive:
        import code
        code.interact(local=locals())
    # output handling
    ret = None
    if rtype == 'string':
        ret = api.output_to_string(memory_handler, results)
    elif rtype == 'python':
        ret = api.output_to_python(memory_handler, results)
    elif rtype == 'json':
        ret = api.output_to_json(memory_handler, results)
    elif rtype == 'pickled':
        ret = api.output_to_pickle(memory_handler, results)
    else:
        raise ValueError('unknown output format')
    print ret
    return

def refresh(args):
    """
    Default function for the refresh command line option.
    Try to map a Structure from a specific offset in memory.
    Returns it in pickled or text format.

    See the command line --help .
    """
    # we need an int
    memory_address = args.addr
    # get the memory handler adequate for the type requested
    memory_handler = _get_memory_handler(args)
    # print output on stdout
    rtype = _get_output_style(args)
    # check the validity of the address
    heap = memory_handler.is_valid_address_value(memory_address)
    if not heap:
        log.error("the address is not accessible in the memoryMap")
        raise ValueError("the address is not accessible in the memoryMap")
    # get the structure name
    modulename, sep, classname = args.struct_name.rpartition('.')
    module = memory_handler.get_model().import_module(modulename)
    struct_type = getattr(module, classname)
    # load the record
    result = api.load_record(memory_handler, struct_type, memory_address)
    results = [result]
    if args.validate:
        my_constraints = None
        if args.constraints_file:
            handler = constraints.ConstraintsConfigHandler()
            my_constraints = handler.read(args.constraints_file.name)
        validation = api.validate_record(memory_handler, result[0], my_constraints)
    if args.interactive:
        import code
        code.interact(local=locals())
    # output handling
    ret = None
    if rtype == 'string':
        ret = api.output_to_string(memory_handler, results)
    elif rtype == 'python':
        ret = api.output_to_python(memory_handler, results)
    elif rtype == 'json':
        ret = api.output_to_json(memory_handler, results)
    elif rtype == 'pickled':
        ret = api.output_to_pickle(memory_handler, results)
    else:
        raise ValueError('unknown output format')
    print ret
    if args.validate:
        print 'Validated', validation
    return

def check_varname_for_type(memory_handler, varname, struct_type):
    done = []
    st = struct_type
    model = memory_handler.get_model()
    ctypes = memory_handler.get_target_platform().get_target_ctypes()
    for v in varname:
        if not hasattr(st, v):
            fields = ["%s: %s" % (n, t) for n, t in basicmodel.get_fields(st)]
            log.error(
                '(%s.)%s does not exists in type %s\n\t%s' %
                ('.'.join(done), v, st, '\n\t'.join(fields)))
            return False
        st = st._get_field_type(v)
        if ctypes.is_pointer_type(st):  # accept pointers
            st = model.get_subtype(st)
        done.append(v)
    return True


def get_varname_value(varname, instance):
    done = []
    var = instance
    for v in varname:
        var = getattr(var, v)
        done.append(v)
    return '%s = \n%s' % ('.'.join(done), var)


def watch(args):
    """
    structname watch vaddr [refreshrate] [varname]
    :param opt:
    :return:
    """
    memory_address = args.addr
    refresh = args.refresh_rate
    varname = args.varname
    # we need an int
    # get the memory handler adequate for the type requested
    memory_handler = _get_memory_handler(args)
    # check the validity of the address
    heap = memory_handler.is_valid_address_value(memory_address)
    if not heap:
        log.error("the address is not accessible in the memoryMap")
        raise ValueError("the address is not accessible in the memoryMap")
    # get the structure name
    modulename, sep, classname = args.struct_name.rpartition('.')
    module = memory_handler.get_model().import_module(modulename)
    struct_type = getattr(module, classname)

    # verify target fieldcompliance
    if varname is not None:
        varname = varname.split('.')
        if not check_varname_for_type(memory_handler, varname, struct_type):
            return False

    # load the record
    result = api.load_record(memory_handler, struct_type, memory_address)
    results = [result]
    # output handling
    output = api.output_to_python(memory_handler, results)
    py_obj = output[0][0]
    # print pyObj
    # print as asked every n secs.
    while True:
        # clear terminal
        print chr(27) + "[2J"
        #
        if varname is None:
            print py_obj
        else:
            print get_varname_value(varname, py_obj)

        if refresh == 0:
            break
        time.sleep(refresh)
        result = api.load_record(memory_handler, struct_type, memory_address)
        results = [result]
        # output handling
        output = api.output_to_python(memory_handler, results)
        py_obj = output[0][0]