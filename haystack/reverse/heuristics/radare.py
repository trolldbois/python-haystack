# -*- coding: utf-8 -*-

#  git clone https://github.com/radare/radare2.git
import logging

#import r2pipe

log = logging.getLogger('radare')


class RadareAnalysis(object):
    """
    Use radare to get more info about non heaps
    """
    def __init__(self, memory_handler):
        self._memory_handler = memory_handler
        self.functions = {}

    def init_all_functions(self):
        for a_map in self._memory_handler.get_mappings():
            self.find_functions(a_map)

    def find_functions(self, mapping):
        fname = mapping._memdumpname
        log.debug('Opening %s', fname)
        # FIXME is that even useful
        import r2pipe
        r2 = r2pipe.open(fname)
        r2.cmd("aaa")
        analysis = r2.cmd("afl")
        print analysis
        res = analysis.split('\n')
        log.debug("len %d - %d", len(analysis), len(res))
        #if len(analysis) > 40:
        #    import pdb
        #    pdb.set_trace()
        nb = 0
        for f_line in res:
            if "0x" not in res:
                continue
            addr, size, bbs, name = f_line.split('  ')
            addr = int(addr, 16)
            if addr == 0x0:
                continue
            size = int(size)
            bbs = int(bbs)
            self.functions[mapping.start+addr] = (size, bbs, name)
            nb += 1
        log.debug('Found %d functions in 0x%x', nb, mapping.start)