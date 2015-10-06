#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import ctypes
import logging
import os
import re
import Levenshtein  # seqmatcher ?
import networkx
import numpy
import struct

from haystack.reverse import config
import haystack.reverse.matchers
from haystack.utils import xrange
from haystack.reverse import searchers
from haystack.reverse import utils
from haystack.reverse import structure
from haystack.reverse.heuristics import dsa

"""
Tools around guessing a field' type and
creating signature for record to compare them.
"""


log = logging.getLogger('signature')

# TODO a Group maker based on field pointer memorymappings and structure
# instance/sizes...


class SignatureGroupMaker:
    """
    From a list of addresses, groups similar signature together.
    HINT: structure should be resolved but not reverse-patternised for arrays...??
    """

    def __init__(self, context, name, addrs):
        self._name = name
        self._structures_addresses = addrs
        self._context = context

    def _init_signatures(self):
        # get text signature for Counter to parse
        # need to force resolve of structures
        self._signatures = []
        decoder = dsa.DSASimple(self._context.memory_handler)
        for addr in map(long, self._structures_addresses):
            # decode the fields
            record = self._context.get_structure_for_address(addr)
            ## record.decodeFields()  # can be long
            decoder.analyze_fields(record)
            # get the signature for the record
            self._signatures.append((addr, self._context.get_structure_for_address(addr).getSignature(True)))
        return

    def make(self):
        self._init_signatures()
        #
        self._similarities = []
        for i, x1 in enumerate(self._signatures[:-1]):
            for x2 in self._signatures[i + 1:]:
                addr1, el1 = x1
                addr2, el2 = x2
                lev = Levenshtein.ratio(el1, el2)  # seqmatcher ?
                if lev > 0.75:
                    #self._similarities.append( ((addr1,el1),(addr2,el2)) )
                    self._similarities.append((addr1, addr2))
                    # we do not need the signature.
        # check for chains
        # TODO      we need a group maker with an iterator to push group
        # proposition to the user
        log.debug('\t[-] Signatures done.')
        return

    def persist(self):
        outdir = config.get_cache_filename(
            config.CACHE_SIGNATURE_GROUPS_DIR,
            self._context.dumpname)
        if not os.path.isdir(outdir):
            os.mkdir(outdir)
        if not os.access(outdir, os.W_OK):
            raise IOError('cant write to %s' % (outdir))
        #
        outname = os.path.sep.join([outdir, self._name])
        ar = utils.int_array_save(outname, self._similarities)
        return

    def isPersisted(self):
        outdir = config.get_cache_filename(
            config.CACHE_SIGNATURE_GROUPS_DIR,
            self._context.dumpname)
        return os.access(os.path.sep.join([outdir, self._name]), os.F_OK)

    def load(self):
        outdir = config.get_cache_filename(
            config.CACHE_SIGNATURE_GROUPS_DIR,
            self._context.dumpname)
        inname = os.path.sep.join([outdir, self._name])
        self._similarities = utils.int_array_cache(inname)
        return

    def getGroups(self):
        return self._similarities


class StructureSizeCache:

    """Loads structures, get their signature (and size) and sort them in
    fast files dictionaries."""

    def __init__(self, ctx):
        self._context = ctx
        self._sizes = None

    def _loadCache(self):
        outdir = config.get_cache_filename(
            config.CACHE_SIGNATURE_SIZES_DIR,
            self._context.dumpname)
        fdone = os.path.sep.join(
            [outdir, config.CACHE_SIGNATURE_SIZES_DIR_TAG])
        if not os.access(fdone, os.R_OK):
            return False
        for myfile in os.listdir(outdir):
            try:
                # FIXME: not sure its -
                # and what that section is about in general.
                addr = int(myfile.split('-')[1], 16)
            except IndexError as e:
                continue  # ignore file

    def cacheSizes(self):
        """Find the number of different sizes, and creates that much numpyarray"""
        # if not os.access
        outdir = config.get_cache_filename(
            config.CACHE_SIGNATURE_SIZES_DIR,
            self._context.dumpname)
        if not os.path.isdir(outdir):
            os.mkdir(outdir)
        if not os.access(outdir, os.W_OK):
            raise IOError('cant write to %s' % (outdir))
        #
        sizes = map(int, set(self._context._malloc_sizes))
        arrays = dict([(s, []) for s in sizes])
        # sort all addr in all sizes..
        [arrays[self._context._malloc_sizes[i]].append(
            long(addr)) for i, addr in enumerate(self._context._malloc_addresses)]
        # saving all sizes dictionary in files...
        for size, lst in arrays.items():
            fout = os.path.sep.join([outdir, 'size.%0.4x' % (size)])
            arrays[size] = utils.int_array_save(fout, lst)
        # saved all sizes dictionaries.
        # tag it as done
        file(
            os.path.sep.join([outdir, config.CACHE_SIGNATURE_SIZES_DIR_TAG]), 'w')
        self._sizes = arrays
        return

    def getStructuresOfSize(self, size):
        if self._sizes is None:
            self.cacheSizes()
        if size not in self._sizes:
            return []
        return numpy.asarray(self._sizes[size])

    def __iter__(self):
        if self._sizes is None:
            self.cacheSizes()
        for size in self._sizes.keys():
            yield (size, numpy.asarray(self._sizes[size]))


class SignatureMaker(searchers.AbstractSearcher):

    '''
    make a condensed signature of the mapping.
    We could then search the signature file for a specific signature
    '''

    NULL = 0x1
    POINTER = 0x2
    # POINTERS = NULL | POINTER # null can be a pointer value so we can
    # byte-test that
    OTHER = 0x4

    def __init__(self, mapping):
        searchers.AbstractSearcher.__init__(self, mapping)
        self.pSearch = haystack.reverse.matchers.PointerSearcher(self.get_search_mapping())
        self.nSearch = haystack.reverse.matchers.NullSearcher(self.get_search_mapping())

    def test_match(self, vaddr):
        ''' return either NULL, POINTER or OTHER '''
        if self.nSearch.test_match(vaddr):
            return self.NULL
        if self.pSearch.test_match(vaddr):
            return self.POINTER
        return self.OTHER

    def search(self):
        ''' returns the memspace signature. Dont forget to del that object, it's big. '''
        self._values = b''
        log.debug(
            'search %s mapping for matching values' %
            (self.get_search_mapping()))
        for vaddr in xrange(
                self.get_search_mapping().start, self.get_search_mapping().end, self.WORDSIZE):
            self._check_steps(vaddr)  # be verbose
            self._values += struct.pack('B', self.test_match(vaddr))
        return self._values

    def __iter__(self):
        ''' Iterate over the mapping to return the signature of that memspace '''
        log.debug(
            'iterate %s mapping for matching values' %
            (self.get_search_mapping()))
        for vaddr in xrange(
                self.get_search_mapping().start, self.get_search_mapping().end, self.WORDSIZE):
            self._check_steps(vaddr)  # be verbose
            yield struct.pack('B', self.test_match(vaddr))
        return


class PointerSignatureMaker(SignatureMaker):

    def test_match(self, vaddr):
        ''' return either POINTER or OTHER '''
        if self.pSearch.test_match(vaddr):
            return self.POINTER
        return self.OTHER


class RegexpSearcher(searchers.AbstractSearcher):

    '''
    Search by regular expression in memspace.
    '''

    def __init__(self, mapping, regexp):
        searchers.AbstractSearcher.__init__(self, mapping)
        self.regexp = regexp
        self.pattern = re.compile(regexp, re.IGNORECASE)

    def search(self):
        ''' find all valid matches offsets in the memory space '''
        self._values = set()
        log.debug(
            'search %s mapping for matching values %s' %
            (self.get_search_mapping(), self.regexp))
        for match in self.get_search_mapping().finditer(
                self.get_search_mapping().mmap().get_byte_buffer()):
            offset = match.start()
            # FIXME, TU what is value for?
            value = match.group(0)
            if isinstance(value, list):
                value = ''.join([chr(x) for x in match.group()])
            vaddr = offset + self.get_search_mapping().start
            self._check_steps(vaddr)  # be verbose
            self._values.add((vaddr, value))
        return self._values

    def __iter__(self):
        ''' Iterate over the mapping to find all valid matches '''
        log.debug(
            'iterate %s mapping for matching values' %
            (self.get_search_mapping()))
        for match in self.pattern.finditer(
                self.get_search_mapping().mmap().get_byte_buffer()):
            offset = match.start()
            value = match.group(0)  # [] of int ?
            if isinstance(value, list):
                value = ''.join([chr(x) for x in match.group()])
            vaddr = offset + self.get_search_mapping().start
            self._check_steps(vaddr)  # be verbose
            yield (vaddr, value)
        return

    def test_match(self, vaddr):
        return True

#EmailRegexp = r'''[a-zA-Z0-9+_\-\.]+@[0-9a-zA-Z][.-0-9a-zA-Z]*.[a-zA-Z]+'''
EmailRegexp = r'''((\"[^\"\f\n\r\t\v\b]+\")|([\w\!\#\$\%\&\'\*\+\-\~\/\^\`\|\{\}]+(\.[\w\!\#\$\%\&\'\*\+\-\~\/\^\`\|\{\}]+)*))@((\[(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))\])|(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))|((([A-Za-z0-9\-])+\.)+[A-Za-z\-]+))'''
URLRegexp = r'''[a-zA-Z0-9]+://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'''
# URIRegexp =
# r'''#^([a-z0-9+\-.]+):([/]{0,2}([a-z0-9\-._~%!\$&'\(\)\*+,;=:]+@)?([\[\]a-z0-9\-._~%!\$&'\(\)\*+,;=:]+(:[0-9]+)?))([a-z0-9\-._~%!\$&'\(\)\*+,;=:@/]*)(\?[\?/a-z0-9\-._~%!\$&'\(\)\*+,;=:@]+)?(\#[a-z0-9\-._~%!\$&'\(\)\*+,;=:@/\?]+)?#i'''
WinFileRegexp = r'''([a-zA-Z]\:)(\\[^\\/:*?<>"|]*(?<![ ]))*(\.[a-zA-Z]{2,6})'''
#WinFileRegexp = r'''(.*?)([^/\\]*?)(\.[^/\\.]*)?'''
IPv4Regexp = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'''
IPv6Regexp = r'''(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))'''
SQLRegexp = r'''(SELECT\s[\w\*\)\(\,\s]+\sFROM\s[\w]+)| (UPDATE\s[\w]+\sSET\s[\w\,\'\=]+)| (INSERT\sINTO\s[\d\w]+[\s\w\d\)\(\,]*\sVALUES\s\([\d\w\'\,\)]+)| (DELETE\sFROM\s[\d\w\'\=]+)'''
CCardRegexp = r'''((4\d{3})|(5[1-5]\d{2}))(-?|\040?)(\d{4}(-?|\040?)){3}|^(3[4,7]\d{2})(-?|\040?)\d{6}(-?|\040?)\d{5}'''
SSNRegexp = r'''\d{3}-\d{2}-\d{4}'''
GUIDRegexp = r'''([A-Fa-f0-9]{32}| [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}| \{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\})'''
# UNCRegexp = r'''((\\\\[a-zA-Z0-9-]+\\[a-zA-Z0-9`~!@#$%^&(){}'._-]+([ ]+[a-zA-Z0-9`~!@#$%^&(){}'._-]+)*)|([a-zA-Z]:))(\\[^ \\/:*?""<>|]+([ ]+[^ \\/:*?""<>|]+)*)*\\?'''
#UNCRegexp = r'(([a-zA-Z]:|\\)\\)?(((\.)|(\.\.)|([^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?))\\)*[^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?'


def looksLikeUTF8(bytearray):
    p = re.compile("\\A(\n" +
                   r"  [\\x09\\x0A\\x0D\\x20-\\x7E]             # ASCII\\n" +
                   r"| [\\xC2-\\xDF][\\x80-\\xBF]               # non-overlong 2-byte\n" +
                   r"|  \\xE0[\\xA0-\\xBF][\\x80-\\xBF]         # excluding overlongs\n" +
                   r"| [\\xE1-\\xEC\\xEE\\xEF][\\x80-\\xBF]{2}  # straight 3-byte\n" +
                   r"|  \\xED[\\x80-\\x9F][\\x80-\\xBF]         # excluding surrogates\n" +
                   r"|  \\xF0[\\x90-\\xBF][\\x80-\\xBF]{2}      # planes 1-3\n" +
                   r"| [\\xF1-\\xF3][\\x80-\\xBF]{3}            # planes 4-15\n" +
                   r"|  \\xF4[\\x80-\\x8F][\\x80-\\xBF]{2}      # plane 16\n" +
                   r")*\\z", re.VERBOSE)

    phonyString = bytearray.encode("ISO-8859-1")
    return p.matcher(phonyString).matches()

'''
lib["email"] = re.compile(r"(?:^|\s)[-a-z0-9_.]+@(?:[-a-z0-9]+\.)+[a-z]{2,6}(?:\s|$)",re.IGNORECASE)
lib["postcode"] = re.compile("[a-z]{1,2}\d{1,2}[a-z]?\s*\d[a-z]{2}",re.IGNORECASE)
lib["zipcode"] = re.compile("\d{5}(?:[-\s]\d{4})?")
lib["ukdate"] = re.compile \
("[0123]?\d[-/\s\.](?:[01]\d|[a-z]{3,})[-/\s\.](?:\d{2})?\d{2}",re.IGNORECASE)
lib["time"] = re.compile("\d{1,2}:\d{1,2}(?:\s*[aApP]\.?[mM]\.?)?")
lib["fullurl"] = re.compile("https?://[-a-z0-9\.]{4,}(?::\d+)?/[^#?]+(?:#\S+)?",re.IGNORECASE)
lib["visacard"] = re.compile("4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["mastercard"] = re.compile("5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["phone"] = re.compile("0[-\d\s]{10,}")
lib["ninumber"] = re.compile("[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-z]",re.IGNORECASE)
lib["isbn"] = re.compile("(?:[\d]-?){9}[\dxX]")
  '''


def makeSizeCaches(dumpname):
    ''' gets all structures instances from the dump, order them by size.'''
    from haystack.reverse import context
    log.debug('\t[-] Loading the context for a dumpname.')
    ctx = context.get_context(dumpname)
    log.debug('\t[-] Make the size dictionnaries.')
    sizeCache = StructureSizeCache(ctx)
    sizeCache.cacheSizes()

    return ctx, sizeCache


def buildStructureGroup(context, sizeCache, optsize=None):
    ''' Iterate of structure instances grouped by size, find similar signatures,
    and outputs a list of groups of similar structures instances.'''
    log.debug("\t[-] Group structures's signatures by sizes.")
    sgms = []
    #
    for size, lst in sizeCache:
        if optsize is not None:
            if size != optsize:
                continue  # ignore different size
        log.debug("\t[-] Group signatures for structures of size %d" % (size))
        sgm = SignatureGroupMaker(context, 'structs.%x' % (size), lst)
        if sgm.isPersisted():
            sgm.load()
        else:
            sgm.make()
            sgm.persist()
        sgms.append(sgm)

        # TODO DEBUG
        # if len(lst) >100:
        #  log.error('too big a list, DELETE THIS ')
        #  continue
        #  #return

        # make a chain and use --originAddr
        log.debug(
            '\t[-] Sort %d structs of size %d in groups' %
            (len(lst), size))
        graph = networkx.Graph()
        # add similarities as linked structs
        graph.add_edges_from(sgm.getGroups())
        # add all structs all nodes . Should spwan isolated graphs
        graph.add_nodes_from(lst)
        subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(
            graph)
        # print 'subgraphs', len(subgraphs)
        chains = [g.nodes() for g in subgraphs]
        # TODO, do not forget this does only gives out structs with similarities.
        # lonely structs are not printed here...
        yield chains


def printStructureGroups(context, chains, originAddr=None):
    chains.sort()
    decoder = dsa.DSASimple(context.memory_handler)
    for chain in chains:
        log.debug('\t[-] chain len:%d' % len(chain))
        if originAddr is not None:
            if originAddr not in chain:
                continue  # ignore chain if originAddr is not in it
        for addr in map(long, chain):
            record = context.get_structure_for_address(addr)
            ##record.decodeFields()  # can be long
            decoder.analyze_fields(record)
            print context.get_structure_for_address(addr).toString()
        print '#', '-' * 78


def graphStructureGroups(context, chains, originAddr=None):
    # TODO change generic fn
    chains.sort()
    decoder = dsa.DSASimple(context.memory_handler)
    graph = networkx.DiGraph()
    for chain in chains:
        log.debug('\t[-] chain len:%d' % len(chain))
        if originAddr is not None:
            if originAddr not in chain:
                continue  # ignore chain if originAddr is not in it
        for addr in map(long, chain):
            record = context.get_structure_for_address(addr)
            ## record.decodeFields()  # can be long
            decoder.analyze_fields(record)
            print context.get_structure_for_address(addr).toString()
            targets = set()
            for f in context.get_structure_for_address(addr).getPointerFields():
                addr_child = f._getValue(0)
                child = context.getStructureForOffset(addr)
                targets.add(('%x' % addr, '%x' % child._vaddr))
            graph.add_edges_from(targets)
        print '#', '-' * 78
    networkx.readwrite.gexf.write_gexf(
        graph,
        config.get_cache_filename(
            config.CACHE_GRAPH,
            context.dumpname))


# TODO next next step, compare struct links in a DiGraph with node ==
# struct size + pointer index as a field.

def makeReversedTypes(context, sizeCache):
    ''' Compare signatures for each size groups.
    Makes a chains out of similar structures. Changes the structure names for a single
    typename when possible. Changes the ctypes types of each pointer field.'''

    log.info(
        '[+] Build groups of similar instances, create a reversed type for each group.')
    for chains in buildStructureGroup(context, sizeCache):
        fixType(context, chains)

    log.info('[+] For each instances, fix pointers fields to newly created types.')
    decoder = dsa.DSASimple(context.memory_handler)
    for s in context.listStructures():
        s.reset()
        ## s.decodeFields()
        decoder.analyze_fields(s)
        for f in s.getPointerFields():
            addr = f._getValue(0)
            if addr in context.heap:
                try:
                    ctypes_type = context.getStructureForOffset(
                        addr).get_ctype()
                # we have escapees, withouth a typed type... saved them from
                # exception
                except TypeError as e:
                    ctypes_type = fixInstanceType(
                        context,
                        context.getStructureForOffset(addr),
                        getname())
                #f.setCtype(ctypes.POINTER(ctypes_type))
                f.set_child_ctype(ctypes.POINTER(ctypes_type))
                f.setComment('pointer fixed')

    log.info('[+] For new reversed type, fix their definitive fields.')
    for revStructType in context.listReversedTypes():
        revStructType.makeFields(context)

    # poitners not in the heap
    # for s in context.listStructures():
    #  for f in s.getPointerFields():
    #    if ctypes.is_void_pointer_type(f.getCtype()):
    #      print s,'has a c_void_p field', f._getValue(0),
    #      print context.getStructureForOffset( f._getValue(0) )

    return context


def makeSignatures(dumpname):
    from haystack.reverse import context
    log.debug('\t[-] Loading the context for a dumpname.')
    ctx = context.get_context(dumpname)
    heap = ctx.heap

    log.info('[+] Make the signatures.')
    sigMaker = SignatureMaker(heap)
    sig = sigMaker.search()
    return ctx, sig


def makeGroupSignature(context, sizeCache):
    ''' From the structures cache ordered by size, group similar instances together. '''
    log.info("[+] Group structures's signatures by sizes.")
    sgms = []
    try:
        for size, lst in sizeCache:
            log.debug(
                "[+] Group signatures for structures of size %d" %
                (size))
            sgm = SignatureGroupMaker(context, 'structs.%x' % (size), lst)
            sgm.make()
            sgm.persist()
            sgms.append(sgm)
    except KeyboardInterrupt as e:
        pass
    return context, sgms

# FIXME: 100 maybe is a bit short
try:
    import pkgutil
    _words = pkgutil.get_data(__name__, config.WORDS_FOR_REVERSE_TYPES_FILE)
except ImportError:
    import pkg_resources
    _words = pkg_resources.resource_string(
        __name__,
        config.WORDS_FOR_REVERSE_TYPES_FILE)

# global
_NAMES = [s.strip() for s in _words.split('\n')[:-1]]
_NAMES_plen = 1


def getname():
    global _NAMES, _NAMES_plen
    if len(_NAMES) == 0:
        _NAMES_plen += 1
        _NAMES = [
            ''.join(x) for x in itertools.permutations(
                _words.split('\n')[
                    :-
                    1],
                _NAMES_plen)]
    return _NAMES.pop()


def fixType(context, chains):
    ''' Fix the name of each structure to a generic word/type name '''
    for chain in chains:
        name = getname()
        log.debug(
            '\t[-] fix type of chain size:%d with name name:%s' %
            (len(chain), name))
        for addr in chain:  # chain is a numpy
            addr = int(addr)
            # FIXME
            instance = context.get_structure_for_address(addr)
            #
            ctypes_type = fixInstanceType(context, instance, name)
    return


def fixInstanceType(context, instance, name):
    # TODO if instance.isFixed, return instance.getCtype()
    instance.setName(name)
    ctypes_type = context.getReversedType(name)
    if ctypes_type is None:  # make type
        ctypes_type = structure.ReversedType.create(context, name)
    ctypes_type.addInstance(instance)
    instance.set_ctype(ctypes_type)
    return ctypes_type


if __name__ == '__main__':
    pass
