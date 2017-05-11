#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Entry points related to reverse. """

import os
import sys

from haystack import argparse_utils
from haystack import cli
from haystack.reverse import api

# the description of the function
REVERSE_DESC = 'Reverse the data structure from the process memory'
REVERSE_SHOW_DESC = 'Show the record at a specific address'
REVERSE_PARENT_DESC = 'List the predecessors pointing to the record at this address'
REVERSE_HEX_DESC = 'Show the Hex values for the record at that address.'


def reverse_argparser(reverse_parser):
    reverse_parser.set_defaults(func=reverse_cmdline)
    return reverse_parser


def reverse_show_argparser(show_parser):
    """ Show function options argument parser """
    show_parser.add_argument('address', type=argparse_utils.int16, help='Record memory address in hex')
    show_parser.set_defaults(func=reverse_show_cmdline)
    return show_parser


def reverse_parents_argparser(parents_parser):
    parents_parser.add_argument('address', type=argparse_utils.int16, action='store', default=None,
                        help='Hex address of the child structure')
    parents_parser.set_defaults(func=show_predecessors_cmdline)
    return parents_parser


def reverse_hex_argparser(hex_parser):
    hex_parser.add_argument('address', type=argparse_utils.int16, action='store', default=None,
                            help='Specify the address of the record, or encompassed by the record')
    hex_parser.set_defaults(func=show_hex)
    return hex_parser


def show_hex(args):
    """ Show the Hex values for the record at that address. """
    memory_handler = cli.get_memory_handler(args)
    process_context = memory_handler.get_reverse_context()
    ctx = process_context.get_context_for_address(args.address)
    try:
        st = ctx.get_record_at_address(args.address)
        print repr(st.bytes)
    except ValueError as e:
        print None
    return


def show_predecessors_cmdline(args):
    """
    Show the predecessors that point to a record at a particular address.
    :param opt:
    :return:
    """
    memory_handler = cli.get_memory_handler(args)
    process_context = memory_handler.get_reverse_context()
    ctx = process_context.get_context_for_address(args.address)
    try:
        child_record = ctx.get_record_at_address(args.address)
    except ValueError as e:
        print None
        return

    records = api.get_record_predecessors(memory_handler, child_record)
    if len(records) == 0:
        print None
    else:
        for p_record in records:
            print '#0x%x\n%s\n' % (p_record.address, p_record.to_string())
    return


def reverse_show_cmdline(args):
    """ Show the record at a specific address. """
    memory_handler = cli.get_memory_handler(args)
    process_context = memory_handler.get_reverse_context()
    ctx = process_context.get_context_for_address(args.address)
    try:
        st = ctx.get_record_at_address(args.address)
        print st.to_string()
    except ValueError:
        print None
    return


def reverse_cmdline(args):
    """ Reverse """
    from haystack.reverse import api as rapi
    # get the memory handler adequate for the type requested
    memory_handler = cli.get_memory_handler(args)
    # do the search
    rapi.reverse_instances(memory_handler)
    return


def main_reverse():
    argv = sys.argv[1:]
    desc = REVERSE_DESC + cli.DUMPTYPE_BASE_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    reverse_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_BASE
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_reverse():
    argv = sys.argv[1:]
    desc = REVERSE_DESC + cli.DUMPTYPE_MINIDUMP_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    reverse_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_MINIDUMP
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def main_reverse_show():
    argv = sys.argv[1:]
    desc = REVERSE_SHOW_DESC + cli.DUMPTYPE_BASE_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    reverse_show_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_BASE
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_reverse_show():
    argv = sys.argv[1:]
    desc = REVERSE_SHOW_DESC + cli.DUMPTYPE_MINIDUMP_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    reverse_show_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_MINIDUMP
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def main_reverse_parents():
    argv = sys.argv[1:]
    desc = REVERSE_PARENT_DESC + cli.DUMPTYPE_BASE_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    reverse_parents_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_BASE
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_reverse_parents():
    argv = sys.argv[1:]
    desc = REVERSE_PARENT_DESC + cli.DUMPTYPE_MINIDUMP_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    reverse_parents_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_MINIDUMP
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def main_reverse_hex():
    argv = sys.argv[1:]
    desc = REVERSE_HEX_DESC + cli.DUMPTYPE_BASE_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_folder_name', type=argparse_utils.readable, help='Use this memory dump folder')
    reverse_hex_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_BASE
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return


def minidump_reverse_hex():
    argv = sys.argv[1:]
    desc = REVERSE_HEX_DESC + cli.DUMPTYPE_MINIDUMP_DESC
    rootparser = cli.base_argparser(program_name=os.path.basename(sys.argv[0]), description=desc)
    rootparser.add_argument('dump_filename', type=argparse_utils.readable, help='Use this memory dump file')
    reverse_hex_argparser(rootparser)
    opts = rootparser.parse_args(argv)
    opts.dumptype = cli.DUMPTYPE_MINIDUMP
    # apply verbosity
    cli.set_logging_level(opts)
    # execute function
    opts.func(opts)
    return
