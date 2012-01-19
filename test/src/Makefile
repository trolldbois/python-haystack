#!/usr/bin/make -f

CFLAGS = -O2 -g -Wall
CPPFLAGS = -O2 -g -Wall
LDFLAGS = -ldl
INCLS = 

EXTRA =

FLAGS= ${INCLS} ${EXTRA}

pid=

.PHONY: 
	
all: test-ctypes1 test-ctypes2 test-ctypes3 test-ctypes4
	
dumps:
	sudo python make.py
	
test-ctypes1: test-ctypes1.c
	$(CC) $(CFLAGS) $<  $(LDFLAGS)  -o $@
	
test-ctypes2: test-ctypes2.cpp
	$(CXX) $(CPPFLAGS) $<  $(LDFLAGS)  -o $@

test-ctypes3: test-ctypes3.c
	$(CC) $(CFLAGS)  $<  $(LDFLAGS)  -o $@

test-ctypes4: test-ctypes4.cpp
	$(CXX) $(CPPFLAGS) $<  $(LDFLAGS)  -o $@

	
clean:
	rm test-ctypes1 test-ctypes2 test-ctypes3


