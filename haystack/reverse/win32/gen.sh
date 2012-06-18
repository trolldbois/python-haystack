#!/bin/sh

h2xml.py -I. winheap7.h -o win7heap.xml 
xml2py.py -kdest win7heap.xml -o win7heap_generated.py
