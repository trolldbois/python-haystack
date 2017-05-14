#!/usr/bin/env python
# -*- coding: utf-8 -*-



from __future__ import print_function

"""Search for a known structure type in a process memory. """

import logging
import time
import sys
import argparse

import os

from haystack import argparse_utils
from haystack import basicmodel
from haystack import constraints
from haystack import dbg
from haystack import dump_loader
from haystack.mappings import vol
from haystack.mappings import rek
from haystack.search import api

log = logging.getLogger('cli')

# the description of the function
SEARCH_DESC = 'Search for instance of a record_type in the allocated memory of a process. '
SHOW_DESC = 'Cast the bytes at this address into a record_type. '
WATCH_DESC = 'Cast the bytes at this address into a record_type and refresh regularly. '
DUMP_DESC = 'Extract the process dump from the OS memory dump in haystack format. '

# some dumptype constants
DUMPTYPE_BASE = 'haystack'
DUMPTYPE_VOLATILITY = 'volatility'
DUMPTYPE_REKALL = 'rekall'
DUMPTYPE_LIVE = 'live'
DUMPTYPE_MINIDUMP = 'minidump'

# the description of the dump type
DUMPTYPE_BASE_DESC = 'The process dump is a folder produced by a haystack-dump script.'
DUMPTYPE_VOL_DESC = 'The process dump is a volatility OS dump. The PID is the targeted process.'
DUMPTYPE_REKALL_DESC = 'The process dump is a rekall OS dump. The PID is the targeted process.'
DUMPTYPE_LIVE_DESC = 'The PID must be a running process.'
DUMPTYPE_MINIDUMP_DESC = 'The process dump is a Minidump (MDMP) process dump.'


class HaystackError(Exception):
    pass


def get_memory_handler(opts):
    if opts.dumptype == DUMPTYPE_BASE:
        loader = dump_loader.ProcessMemoryDumpLoader(opts.dump_folder_name)
        memory_handler = loader.make_memory_handler()
    elif opts.dumptype == DUMPTYPE_VOLATILITY:
        mapper = vol.VolatilityProcessMapper(opts.dump_filename, "WinXPSP2x86", opts.pid)
        memory_handler = mapper.make_memory_handler()
    elif opts.dumptype == DUMPTYPE_REKALL:
        mapper = rek.RekallProcessMapper(opts.dump_filename, opts.pid)
        memory_handler = mapper.make_memory_handler()
    elif opts.dumptype == DUMPTYPE_LIVE:
        memory_handler = dbg.make_local_process_memory_handler(pid=opts.pid, use_mmap=opts.mmap)
    elif opts.dumptype == DUMPTYPE_MINIDUMP:
        from haystack.mappings import minidump
        loader = minidump.MDMP_Mapper(opts.dump_filename)
        memory_handler = loader.make_memory_handler()
    else:
        raise RuntimeError('dump type has no case support. %s', opts.dumptype)
    return memory_handler


def get_output(memory_handler, results, rtype):
    if rtype == 'string':
        ret = api.output_to_string(memory_handler, results)
    elif rtype == 'python':
        # useful in interactive mode
        ret = api.output_to_python(memory_handler, results)
    elif rtype == 'json':
        ret = api.output_to_json(memory_handler, results)
    elif rtype == 'pickled':
        ret = api.output_to_pickle(memory_handler, results)
    else:
        raise ValueError('unknown output format')
    return ret


def dump_process(opts):
    """ Extract the process dump from the OS memory dump in haystack format. """
    if opts.dumptype == DUMPTYPE_VOLATILITY:
        pass
    elif opts.dumptype == DUMPTYPE_REKALL:
        from haystack.mappings import rek
        rek.rekall_dump_to_haystack(opts.dump_filename, opts.pid, opts.output_folder_name)
    return


def search_cmdline(args):
    """ Search for instance of a record_type in the allocated memory of a process. """
    # get the memory handler adequate for the type requested
    memory_handler = get_memory_handler(args)
    # try to load constraints
    my_constraints = None
    if args.constraints_file:
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read(args.constraints_file.name)
    # get the python record type
    modulename, sep, classname = args.record_type_name.rpartition('.')
    module = None
    try:
        module = memory_handler.get_model().import_module(modulename)
    except ImportError as e:
        log.error('sys.path is %s', sys.path)
        raise e
    record_type = getattr(module, classname)
    # do the search
    results = api.search_record(memory_handler, record_type, my_constraints, extended_search=args.extended)
    # output handling
    try:
        ret = get_output(memory_handler, results, args.output)
        # print output on stdout
        print(ret)
    except Exception as e:
        log.error(e)
    finally:
        if args.interactive:
            print('results are local variable "results"')
            import code
            code.interact(local=locals())
    return


def show_cmdline(args):
    """Cast the bytes at this address into a record_type. """
    # we need an int
    memory_address = args.address
    # get the memory handler adequate for the type requested
    memory_handler = get_memory_handler(args)
    # check the validity of the address
    heap = memory_handler.is_valid_address_value(memory_address)
    if not heap:
        log.error("the address is not accessible in the memoryMap")
        raise ValueError("the address is not accessible in the memoryMap")
    # get the structure name
    modulename, sep, classname = args.record_type_name.rpartition('.')
    module = None
    try:
        module = memory_handler.get_model().import_module(modulename)
    except ImportError as e:
        log.error('sys.path is %s', sys.path)
        raise e
    record_type = getattr(module, classname)
    # load the record
    result = api.load_record(memory_handler, record_type, memory_address)
    results = [result]
    # validate if required
    validation = None
    if args.constraints_file:
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read(args.constraints_file.name)
        validation = api.validate_record(memory_handler, result[0], my_constraints)
    # output handling
    ret = None
    try:
        ret = get_output(memory_handler, results, args.output)
        # print output on stdout
        print(ret)
        if args.constraints_file:
            print('Validated', validation)
    except Exception as e:
        log.error(e)
    finally:
        if args.interactive:
            print('results are local variable "results"')
            import code
            code.interact(local=locals())
    return


def check_varname_for_type(memory_handler, varname, struct_type):
    done = []
    st = struct_type
    model = memory_handler.get_model()
    ctypes = memory_handler.get_target_platform().get_target_ctypes()
    for v in varname:
        if not hasattr(st, v):
            fields = ["%s: %s" % (n, t) for n, t in basicmodel.get_fields(st)]
            log.error('(%s.)%s does not exists in type %s\n\t%s', '.'.join(done), v, st, '\n\t'.join(fields))
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
    """Cast the bytes at this address into a record_type and refresh regularly. """
    memory_address = args.addr
    refresh = args.refresh_rate
    varname = args.varname
    # get the memory handler adequate for the type requested
    memory_handler = get_memory_handler(args)
    # check the validity of the address
    heap = memory_handler.is_valid_address_value(memory_address)
    if not heap:
        log.error("the address is not accessible in the memoryMap")
        raise ValueError("the address is not accessible in the memoryMap")
    # get the structure name
    modulename, sep, classname = args.record_type_name.rpartition('.')
    module = None
    try:
        module = memory_handler.get_model().import_module(modulename)
    except ImportError as e:
        log.error('sys.path is %s', sys.path)
        raise e
    record_type = getattr(module, classname)
    # verify target fieldcompliance
    if varname is not None:
        varname = varname.split('.')
        if not check_varname_for_type(memory_handler, varname, record_type):
            return False
    # load the record
    result = api.load_record(memory_handler, record_type, memory_address)
    results = [result]
    # output handling
    output = api.output_to_python(memory_handler, results)
    # _get_output(memory_handler, results, rtype):
    # Conflicts with varname
    py_obj = output[0][0]
    # print pyObj
    # print as asked every n secs.
    while True:
        # clear terminal
        print(chr(27) + "[2J")
        #
        if varname is None:
            print(py_obj)
        else:
            print(get_varname_value(varname, py_obj))

        if refresh == 0:
            break
        time.sleep(refresh)
        result = api.load_record(memory_handler, record_type, memory_address)
        results = [result]
        # output handling
        output = api.output_to_python(memory_handler, results)
        py_obj = output[0][0]


def base_argparser(program_name, description):
    """ Base options shared by all console scripts """
    rootparser = argparse.ArgumentParser(prog=program_name, description=description)
    verbosity = rootparser.add_mutually_exclusive_group(required=False)
    verbosity.add_argument('--debug', dest='debug', action='store_true', help='Set verbosity to DEBUG')
    verbosity.add_argument('--quiet', dest='quiet', action='store_true', help='Set verbosity to ERROR only')
    rootparser.add_argument('--interactive', dest='interactive', action='store_true',
                            help='drop to python command line after action')
    rootparser.add_argument('--nommap', dest='mmap', action='store_false', help='disable mmap()-ing')
    return rootparser


def search_argparser(search_parser):
    """ Search function options argument parser """
    search_parser.add_argument('record_type_name', type=str,
                               help='Python record type name. Module must be in Python path')
    search_parser.add_argument('--constraints_file', type=argparse.FileType('r'),
                               help='Filename that contains Constraints for the record types in the module')
    search_parser.add_argument('--extended', action='store_true',
                               help='Do not restrict the search to allocated chunks')
    search_parser.add_argument('--hint', type=argparse_utils.int16,
                               help='Restrict the search to the memory page containing this hint address')
    search_parser.set_defaults(func=search_cmdline)
    return search_parser


def show_argparser(show_parser):
    """ Show function options argument parser """
    show_parser.add_argument('record_type_name', type=str,
                             help='Python record type name. Module must be in Python path')
    show_parser.add_argument('address', type=argparse_utils.int16, help='Record memory address in hex')
    show_parser.add_argument('--constraints_file', type=argparse.FileType('r'),
                             help='Filename that contains Constraints for the record types in the module. '
                             'The validation results will be shown on stdout.')
    show_parser.set_defaults(func=show_cmdline)
    return show_parser


def watch_argparser(watch_parser):
    """ Watch function options argument parser """
    # only useful for live PID. Not rekall/vol.
    watch_parser.add_argument('record_type_name', type=str,
                              help='Python record type name. Module must be in Python path')
    watch_parser.add_argument('address', type=argparse_utils.int16, help='Structure memory address')
    watch_parser.add_argument('refresh_rate', type=int, default=0, help='Seconds between refresh')
    watch_parser.add_argument('varname', type=str, default=None,
                              help='structure member name (eg. pointername.valuename)')
    watch_parser.set_defaults(func=watch)
    return watch_parser


def dump_argparser(dump_parser):
    """ Dumper function options argument parser """
    # FIXME createthe rekall/vol dumpers.
    # only useful for live PID. Not rekall/vol.
    dump_parser.add_argument('output_folder_name', type=str, help='Output to this memory dump folder')
    dump_parser.set_defaults(func=dump_process)
    return dump_parser


def output_argparser(rootparser):
    """ Output choices options argument parser """
    output = rootparser.add_mutually_exclusive_group(required=False)
    output.add_argument('--string', dest='output', action='store_const', const='string',
                        help='Print results as human readable string')
    output.add_argument('--json', dest='output', action='store_const', const='json',
                        help='Print results as json readable string')
    # useful in interactive mode
    output.add_argument('--python', dest='output', action='store_const', const='python',
                        help='Print results as python code')
    output.add_argument('--pickled', dest='output', action='store_const', const='pickled',
                        help='Print results as pickled string')
    output.set_defaults(output='string')
    return rootparser


def set_logging_level(opts):
    level = logging.INFO
    if opts.debug:
        level = logging.DEBUG
    elif opts.quiet:
        level = logging.ERROR
    #
    if opts.debug:
        flog = os.path.normpath('log')
        # FORMAT = '%(relativeCreated)d %(message)s'
        # logging.basicConfig(format=FORMAT, level=level, filename=flog, filemode='w')
        logging.basicConfig(level=level, filename=flog, filemode='w')
        print ('[+] **** COMPLETE debug log to %s' % flog)
    else:
        logging.basicConfig(level=level)
    # 2.6, 2.7 compat
    sh = logging.StreamHandler(sys.stdout)
    logging.getLogger('haystack').addHandler(sh)
    return


def main_search():
    # sys.path.append(os.getcwd())
    argv = sys.argv[1:]
    desc = SEARCH_DESC + DUMPTYPE_BASE_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    search_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_BASE
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def main_show():
    argv = sys.argv[1:]
    desc = SHOW_DESC + DUMPTYPE_BASE_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    show_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_BASE
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def live_search():
    argv = sys.argv[1:]
    desc = SEARCH_DESC + DUMPTYPE_LIVE_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('pid', type=int, help='Target PID on the local system')
    search_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_LIVE
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def live_show():
    argv = sys.argv[1:]
    desc = SHOW_DESC + DUMPTYPE_LIVE_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('pid', type=int, help='Target PID on the local system')
    show_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_LIVE
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def live_watch():
    argv = sys.argv[1:]
    desc = WATCH_DESC + DUMPTYPE_LIVE_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('pid', type=int, help='Target PID on the local system')
    watch_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_LIVE
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def volatility_search():
    argv = sys.argv[1:]
    desc = SEARCH_DESC + DUMPTYPE_VOL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    search_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_VOLATILITY
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def volatility_show():
    argv = sys.argv[1:]
    desc = SHOW_DESC + DUMPTYPE_VOL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    show_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_VOLATILITY
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def volatility_dump():
    argv = sys.argv[1:]
    desc = DUMP_DESC + DUMPTYPE_VOL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    dump_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_VOLATILITY
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def rekall_search():
    argv = sys.argv[1:]
    desc = SEARCH_DESC + DUMPTYPE_REKALL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    search_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_REKALL
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def rekall_show():
    argv = sys.argv[1:]
    desc = SHOW_DESC + DUMPTYPE_REKALL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    show_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_REKALL
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def rekall_dump():
    argv = sys.argv[1:]
    desc = DUMP_DESC + DUMPTYPE_REKALL_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    rootparser.add_argument('pid', type=int, help='Target PID in the OS memory dump')
    dump_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_REKALL
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_search():
    argv = sys.argv[1:]
    desc = SEARCH_DESC + DUMPTYPE_MINIDUMP_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    search_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_MINIDUMP
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_show():
    argv = sys.argv[1:]
    desc = SHOW_DESC + DUMPTYPE_MINIDUMP_DESC
    rootparser = base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    show_argparser(rootparser)
    output_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = DUMPTYPE_MINIDUMP
    # apply verbosity
    set_logging_level(opts)
    # execute function
    opts.func(opts)
    return

