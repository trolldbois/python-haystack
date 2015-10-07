# -*- coding: utf-8 -*-

"""Default configuration for filenames, output directories and such."""

import logging
import shutil

import os

log = logging.getLogger('config')


cacheDir = os.path.normpath('/tmp/')
imgCacheDir = os.path.sep.join([cacheDir, 'img'])
commentMaxSize = 64
#
DUMPNAME_INDEX_FILENAME = '_memory_handler'
CACHE_NAME = 'cache'
CACHE_STRUCT_DIR = 'structs'
# cache file names
CACHE_GENERATED_PY_HEADERS_VALUES = 'headers_values.py'
CACHE_GENERATED_PY_HEADERS = 'headers.py'
CACHE_HS_POINTERS_VALUES = 'heap+stack.pointers.values'
CACHE_HEAP_ADDRS = 'heap.pointers.offsets'
CACHE_HEAP_VALUES = 'heap.pointers.values'
CACHE_STACK_ADDRS = 'stack.pointers.offsets'
CACHE_STACK_VALUES = 'stack.pointers.values'
CACHE_ALL_PTRS_ADDRS = 'all.pointers.offsets'
CACHE_ALL_PTRS_VALUES = 'all.pointers.values'
CACHE_FUNCTION_NAMES = 'names.pointers.functions'
CACHE_STRUCTURES = 'structures'
CACHE_MALLOC_CHUNKS_ADDRS = 'mchunks.addrs'
CACHE_MALLOC_CHUNKS_SIZES = 'mchunks.sizes'
CACHE_CONTEXT = 'ctx'
CACHE_GRAPH = 'graph.gexf'
DIFF_PY_HEADERS = 'diff_headers'
CACHE_SIGNATURE_SIZES_DIR = 'structs.sizes.d'
CACHE_SIGNATURE_SIZES_DIR_TAG = 'done'
CACHE_SIGNATURE_GROUPS_DIR = 'structs.groups.d'
REVERSED_TYPES_FILENAME = 'reversed_types.py'
SIGNATURES_FILENAME = 'signatures'
WORDS_FOR_REVERSE_TYPES_FILE = 'data/words.100'

def create_cache_folder_name(dumpname):
    folder = get_cache_folder_name(dumpname)
    if not os.access(folder, os.F_OK):
        os.mkdir(folder)
    return

def remove_cache_folder(dumpname):
    folder = get_cache_folder_name(dumpname)
    if os.access(folder, os.F_OK):
        shutil.rmtree(folder)
    return

def get_cache_folder_name(dumpname):
    root = os.path.abspath(dumpname)
    return os.path.sep.join([root, CACHE_NAME])

def get_cache_filename(typ, dumpname, address):
    """
    Returns a filename for caching a type of data based on the dump filename.

    :param typ: one of Config.CACHE_XX types.
    :param dumpname: the dumpname to get the cache folder
    :param address: a optional unique identifier
    :return:
    """
    fname = typ
    if address is not None:
        fname = '%x.%s' % (address, typ)
    else:
        log.warning('usage without uuid')
        import pdb
        pdb.set_trace()
    return os.path.sep.join([get_cache_folder_name(dumpname), fname])

def get_record_cache_folder_name(dumpname):
    """
    Returns a dirname for caching the structures based on the dump filename.

    dumpname: the dump file name.
    """
    root = os.path.abspath(dumpname)
    return os.path.sep.join([root, CACHE_NAME, CACHE_STRUCT_DIR])
