#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

"""
This module holds some basic utils function.
"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import string

import encodings

log = logging.getLogger('re_string')

#
# TODO: need a rfind-style function (rfind_utf16). otherwise O(n2) is laughing on you in struct/fields evaluation.
# TODO: put heuristics of fields determination and structures algos in subpackages.
# Field and structures should be POPOs - not controllers.
#
#


# nonprintable=[c for c in '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f']
# control_chars = ''.join(map(unichr, range(0,32) + range(127,160)))

def is_printable(c):
    x = ord(c)
    if 126 < x:
        # if 159 < x: # ascii 8 bits... lets put it aside...
        #  return True
        return False
    # else
    if 31 < x:
        return True
    if x == 9 or x == 10 or x == 13:
        return True
    # if x < 32:
    return False

utf_valid_cc = ['\x00']

_py_encodings = set(encodings.aliases.aliases.values())
#  except IOError: # TODO delete bz2 and gzip
#  except TypeError: # TODO delete hex_codec
#  except ValueError: # TODO delete uu_encode
_py_encodings.remove('mbcs')
_py_encodings.remove('hex_codec')
_py_encodings.remove('uu_codec')
_py_encodings.remove('bz2_codec')
_py_encodings.remove('zlib_codec')
_py_encodings.remove('base64_codec')
_py_encodings.remove('tactis')
_py_encodings.remove('rot_13')
_py_encodings.remove('quopri_codec')

# perf test, string.printable is limited to ascii anyway
# ...
#
# TODO you are probably better of accepting only NULL terminated string
# or string terminated by the end of the structure.

_py_encodings = set(['ascii',
                     'latin_1',
                     'iso8859_15',
                     'utf_8',
                     'utf_16le',
                     'utf_32le',
                     ])


class Nocopy():

    def __init__(self, bytes, start, end):
        self.bytes = bytes
        if start < 0:
            start = len(bytes) + start
        if end < 0:
            end = len(bytes) + end
        # print '%s < %s <= %s'%(start, end, len(bytes))
        assert(end <= len(bytes))
        assert(start < end)
        assert(start >= 0)
        self.start = start
        self.end = end
        # print 'got',self.bytes[self.start:self.end]

    def __getitem__(self, i):
        if i >= 0:
            return self.bytes[self.start + i]
        else:
            return self.bytes[self.end + i]

    # end defaults to int.max, not -1
    def __getslice__(self, start=0, end=-1, step=1):
        if (end > self.end - self.start):  # len(self)
            end = self.end - self.start
        if step == 1:
            if start >= 0 and end >= 0:
                return Nocopy(self.bytes, self.start + start, self.start + end)
            elif start < 0 and end < 0:
                return Nocopy(self.bytes, self.end + start, self.end + end)
        else:  # screw you
            return self.bytes[start:end:step]

    def __eq__(self, o):
        to = type(o)
        # print self.bytes[self.start:self.end], '==',o
        if issubclass(to, str) and self.bytes == o:
            return self.start == 0 and self.end == len(o)
        elif issubclass(to, Nocopy):
            return self.bytes[self.start:self.end] == o.bytes[o.start:o.end]
        # else:
        return self.bytes[self.start:self.end] == o

    def __len__(self):
        return self.end - self.start


def _rfind_utf16(bytesarray, longerThan=7):
    '''@returns index of start string'''
    if len(bytesarray) < 4:
        return -1
    i = len(bytesarray) - 2
    # give one shot 'x000'
    if (bytesarray[i + 1] == '\x00' and bytesarray[i] == '\x00'):
        # print 'first', bytesarray[i]
        i -= 2
    while i >= 0 and (bytesarray[i + 1] == '\x00' and bytesarray[i] != '\x00'):
        # print 'then %s and \\x00 '%bytesarray[i]
        i -= 2
    # fix last row
    i += 2
    if i == len(bytesarray):
        return -1
    # print 'bytearray i ',i, len(bytesarray)
    size = len(bytesarray) - i
    #uni = bytesarray[i:]
    #size = len(uni)
    if size > longerThan:
        return i
    return -1


def rfind_utf16(bytes, offset, size, aligned, word_size):
    """
    @returns index from offset where utf16 was found
    If the result must be aligned,
        a) it is assumed that the bytes index 0 is aligned.
        b) any misaligned result will be front-truncated

    :param bytes: the data buffer
    :param offset: the offset in the data buffer
    :param size: the size of the scope in the buffer
    :param aligned: indicate if the result string must be aligned with word boundaries
    :param word_size: the size of a word
    :return:
    """
    # print offset, offset+size
    bytes_nocp = Nocopy(bytes, offset, offset + size)
    index = _rfind_utf16(bytes_nocp)
    if aligned and index > -1:
        # align results
        if index % word_size:
            index += index % word_size
        if index > offset + size - word_size:
            return -1
    return index


def find_ascii(bytes, offset, size):
    '''@returns index from offset where printable ascii was found'''
    bytes_nocp = Nocopy(bytes, offset, offset + size)
    i = offset
    end = offset + size
    while i < end and is_printable(bytes[i]):
        i += 1
    size = i - offset
    if size > 3:
        return 0, size
    return -1, -1


def try_decode_string(bytesarray, longerThan=3):
    ''' try to read string. Null terminated or not
    TODO , maybe check for \x00 in index 0 for utf16 and utf32.
    '''
    if len(bytesarray) <= longerThan:
        return False
    i = bytesarray.find('\x00')
    if i == -1:
        # find longuest readable
        for i, c in enumerate(bytesarray):
            if not is_printable(c):
                break
        if i <= longerThan:
            return False
        readable = bytesarray[:i + 1]
        ustrings = testAllEncodings(bytesarray[:i + 1])
    else:
        ustrings = testAllEncodings(bytesarray)
    # all cases
    ustrings = [(l, enc, ustr) for l, enc, ustr in ustrings if l > longerThan]
    if len(ustrings) == 0:
        return False
    else:  # if len(ustrings) > 5 : # probably an ascii string
        valid_strings = []
        i = 0
        for size, codec, chars in ustrings:
            log.debug('%s %s' % (codec, repr(chars)))
            skip = False
            first = None
            # check not printable chars ( us ascii... )
            for i, c in enumerate(chars):
                # last , NULL terminated. Last because testEncodings should cut
                # at '\x00'
                if (c == '\x00'):
                    break
                if not is_printable(c):
                    skip = True
                    if i <= longerThan:
                        break
                    log.debug(
                        'Not a full string, %s/%d is non printable characters "%s..."' %
                        (repr(c),
                         i,
                         chars[
                            :25]))
                    # else: valid string, but shorter, non null terminated
                    # FIXME this is BUGGY, utf-16 can also considers single
                    # bytes.
                    sizemultiplier = len('\x20'.encode(codec))
                    slen = sizemultiplier * i
                    log.debug('shorten at %d - %s' % (slen, chars[:i]))
                    valid_strings.append((slen, codec, chars[:i]))
                    break
            if skip:
                continue
            # else
            if codec in ['utf_16le', 'utf_32le']:
                if bytesarray[1] not in utf_valid_cc:
                    log.debug(
                        'That %s value, with cc %s - not valid ' %
                        (codec, repr(
                            bytesarray[1])))
                    continue
            log.debug('valid entry %s' % (chars))
            valid_strings.append((size, codec, chars))
        if len(valid_strings) > 0:
            valid_strings.sort(reverse=True)
            return valid_strings[0]
        return False


def startsWithNulTerminatedString(bytesarray, longerThan=3):
    ''' if there is no \x00 termination, its not a string
    that means that if we have a bad pointer in the middle of a string,
    the first part will not be understood as a string'''
    i = bytesarray.find('\x00')
    if i == -1:
        return False
    else:
        ustrings = testAllEncodings(bytesarray)
        ustrings = [(l, enc, ustr)
                    for l, enc, ustr in ustrings if l > longerThan]
        if len(ustrings) == 0:
            return False
        else:  # len(ustrings) > 5 : # probably an ascii string
            notPrintableBool = True
            ustring = [[]]
            i = 0
            for ustring in ustrings:
                #ustring = [(l,enc,s) for l,enc,s in ustrings if enc == 'ascii' ]
                # test ascii repr
                # if len(ustring) != 1:
                #  asciis = ustrings # only printable chars even in utf
                size = ustring[0]
                codec = ustring[1]
                chars = ustring[2]
                log.debug('%s %s' % (codec, repr(chars)))
                # check not printable
                notPrintable = []
                for i, c in enumerate(chars):
                    if c not in string.printable:
                        notPrintable.append((i, c))
                if (len(notPrintable) / float(len(chars))) > 0.5:
                    log.debug(
                        'Not a string, %d/%d non printable characters "%s..."' %
                        (len(notPrintable),
                         i,
                         chars[
                            :25]))
                    continue
                else:
                    return ustring
            return False

# AnonymousStruct_48_182351808_1:


def testAllEncodings(bytesarray):
    res = []
    for codec in _py_encodings:
        length, my_str = testEncoding(bytesarray, codec)
        if length != -1:
            res.append((length, codec, my_str))
    res.sort(reverse=True)
    log.debug('%d valid decodes: \n%s' % (len(res), str(res)))
    return res


def testUTF8(bytesarray):
    return testEncoding(bytesarray, 'UTF-8')


def testUTF16(bytesarray):
    return testEncoding(bytesarray, 'UTF-16le')


def testUTF32(bytesarray):
    return testEncoding(bytesarray, 'UTF-32le')


def testEncoding(bytesarray, encoding):
    ''' test for null bytes on even bytes
    this works only for western txt in utf-16
    '''
    sizemultiplier = len('\x20'.encode(encoding))
    #log.debug('size: %d encoding: %s'%(sizemultiplier, encoding))
    try:
        ustr = bytesarray.decode(encoding)
    except UnicodeDecodeError:
        log.debug(
            'UnicodeDecodeError: %s did not decode that len: %d' %
            (encoding, len(bytesarray)))
        # print repr(bytesarray)
        return -1, None
    except Exception as e:
        log.error('Error using encoding %s' % (encoding))
        raise e
    i = ustr.find('\x00')
    if i == -1:
        log.debug('%s was ok - but no NULL' % (encoding))
        end = len(ustr)
        # return -1, None
    else:
        # include NULL
        end = i + 1

    slen = sizemultiplier * end
    log.debug('%s is ok - with len %d' % (encoding, slen))
    return (slen, ustr[:end])
