# -*- coding: utf-8 -*-

from haystack.constraints import NotNull


# from test.src.ctypes7_gen64 import *
# model.build_python_class_clones(sys.module[__name__])


def populate():
    struct_Node.expectedValues = {
        "val1": [0xdeadbeef],
        "ptr2": [NotNull],  # == self
    }
