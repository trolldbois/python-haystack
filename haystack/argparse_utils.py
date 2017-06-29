#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os

"""Some helpers for argparse."""


def readable(f):
    """Validates if the pathname is readable (dir or file)."""
    f = os.path.normpath(f)
    if not os.access(f, os.F_OK | os.R_OK):
        raise argparse.ArgumentTypeError("%s is not readable." % f)
    return f


def writeable(f):
    """Validates if the pathname is writable (dir or file)."""
    f = os.path.normpath(f)
    if os.access(f, os.F_OK):
        if not os.access(f, os.W_OK):
            raise argparse.ArgumentTypeError("%s is not writable." % f)
    else:
        raise argparse.ArgumentTypeError("%s is not writable." % f)
    return f


def int16(s):
    """Validates an hexadecimal (0x...) value"""
    try:
        i = int(s, 16)
    except Exception as e:
        raise argparse.ArgumentTypeError(e)
    return i

