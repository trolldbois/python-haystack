# -*- coding: utf-8 -*-

from past.builtins import long
import logging
import pickle

import json

from haystack.search import searcher
from haystack.outputters import text
from haystack.outputters import python
from haystack import listmodel

log = logging.getLogger('api')


class HaystackError(Exception):
    pass


def search_record(memory_handler, record_type, search_constraints=None, extended_search=False):
    """
    Search a record in the memory dump of a process represented
    by memory_handler.

    The record type must have been imported using haystack functions.

    If constraints exists, they will be considered during the search.

    :param memory_handler: IMemoryHandler
    :param record_type: a ctypes.Structure or ctypes.Union from a module imported by haystack
    :param search_constraints: IModuleConstraints to be considered during the search
    :param extended_search: boolean, use allocated chunks only per default (False)
    :rtype a list of (ctypes records, memory offset)
    """
    if extended_search:
        my_searcher = searcher.AnyOffsetRecordSearcher(memory_handler, search_constraints)
        return my_searcher.search(record_type)
    my_searcher = searcher.RecordSearcher(memory_handler, search_constraints)
    return my_searcher.search(record_type)


def search_record_hint(memory_handler, record_type, hint, search_constraints=None, extended_search=False):
    """
    Search a record in the memory dump of a process, but only on the memory page containing the hinted address.

    The record type must have been imported using haystack functions.

    If constraints exists, they will be considered during the search.

    :param memory_handler: IMemoryHandler
    :param record_type: a ctypes.Structure or ctypes.Union from a module imported by haystack
    :param search_constraints: IModuleConstraints to be considered during the search
    :param extended_search: boolean, use allocated chunks only per default (False)
    :rtype a list of (ctypes records, memory offset)
    """
    hint_mapping = memory_handler.get_mapping_for_address(hint)
    if extended_search:
        my_searcher = searcher.AnyOffsetRecordSearcher(memory_handler,
                                                       my_constraints=search_constraints,
                                                       target_mappings=[hint_mapping])
        return my_searcher.search(record_type)
    my_searcher = searcher.RecordSearcher(memory_handler,
                                          my_constraints=search_constraints,
                                          target_mappings=[hint_mapping])
    return my_searcher.search(record_type)


# FIXME TODO change for results == ctypes
def output_to_string(memory_handler, results):
    """
    Transform ctypes results in a string format
    :param memory_handler: IMemoryHandler
    :param results: results from the search_record
    :return:
    """
    if not isinstance(results, list):
        raise TypeError('Feed me a list of results')
    parser = text.RecursiveTextOutputter(memory_handler)
    ret = '['
    for ss, addr in results:
        ret += "# --------------- 0x%lx \n%s" % (addr, parser.parse(ss))
        pass
    ret += ']'
    return ret


def output_to_python(memory_handler, results):
    """
    Transform ctypes results in a non-ctypes python object format
    :param memory_handler: IMemoryHandler
    :param results: results from the search_record
    :return:
    """
    if not isinstance(results, list):
        raise TypeError('Feed me a list of results')
    # also generate POPOs
    my_model = memory_handler.get_model()
    pythoned_modules = my_model.get_pythoned_modules().keys()
    for module_name, module in my_model.get_imported_modules().items():
        if module_name not in pythoned_modules:
            my_model.build_python_class_clones(module)
    # parse and generate instances
    parser = python.PythonOutputter(memory_handler)
    ret = [(parser.parse(ss), addr) for ss, addr in results]
    # last check to clean the structure from any ctypes Structure
    if python.findCtypesInPyObj(memory_handler, ret):
        raise HaystackError(
            'Bug in framework, some Ctypes are still in the return results. Please Report test unit.')
    return ret


def output_to_json(memory_handler, results):
    """
    Transform ctypes results in a json format
    :param memory_handler: IMemoryHandler
    :param results: results from the search_record
    :return:
    """
    if not isinstance(results, list):
        raise TypeError('Feed me a list of results')
    ret = output_to_python(memory_handler, results)
    # cirular refs kills it check_circular=False,
    return json.dumps(ret, default=python.json_encode_pyobj)


def output_to_pickle(memory_handler, results):
    """
    Transform ctypes results in a pickled format.
    To load the pickled objects, you need to have haystack in your path.
    
    :param memory_handler: IMemoryHandler
    :param results: results from the search_record
    :return:
    """
    if not isinstance(results, list):
        raise TypeError('Feed me a list of results')
    ret = output_to_python(memory_handler, results)
    return pickle.dumps(ret)


def load_record(memory_handler, struct_type, memory_address, load_constraints=None):
    """
    Load a record from a specific address in memory.
    You could use that function to monitor a specific record from memory after a refresh.

    :param memory_handler: IMemoryHandler
    :param struct_type: a ctypes.Structure or ctypes.Union
    :param memory_address: long
    :param load_constraints: IModuleConstraints to be considered during loading
    :return: (ctypes record instance, validated_boolean)
    """
    # FIXME, is number maybe ?
    if not isinstance(memory_address, long) and not isinstance(memory_address, int):
        raise TypeError('Feed me a long memory_address')
    # we need to give target_mappings so not to trigger a heap resolution
    my_loader = searcher.RecordLoader(memory_handler, load_constraints, target_mappings=memory_handler.get_mappings())
    return my_loader.load(struct_type, memory_address)


def validate_record(memory_handler, instance, record_constraints=None, max_depth=10):
    """
    Validate a loaded record against constraints.

    :param memory_handler: IMemoryHandler
    :param instance: a ctypes record
    :param record_constraints: IModuleConstraints to be considered during validation
    :return:
    """
    validator = listmodel.ListModel(memory_handler, record_constraints)
    return validator.load_members(instance, max_depth)

