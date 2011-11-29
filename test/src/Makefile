#!/usr/bin/make -f

CFLAGS = -O2 -g -Wall
CPPFLAGS = -O2 -g -Wall
LDFLAGS = -ldl
INCLS = 

EXTRA =

FLAGS= ${INCLS} ${EXTRA}



.PHONY:
	


test-ctypes1: test-ctypes1.c
	$(CC) $(CFLAGS)  $<  $(LDFLAGS)  -o $@
	
test-ctypes2: test-ctypes2.cpp
	$(CXX) $(CPPFLAGS) $<  $(LDFLAGS)  -o $@




