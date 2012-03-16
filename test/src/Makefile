#!/usr/bin/make -f

CFLAGS = -O2 -g -Wall
CPPFLAGS = -O2 -g -Wall
LDFLAGS = -ldl
INCLS = 

EXTRA =

FLAGS= ${INCLS} ${EXTRA}

pid=

H2XML=h2xml.py
XML2PY=xml2py.py

.PHONY: 
	
all: test-ctypes1 test-ctypes2 test-ctypes3 test-ctypes4

py: test-ctypes1.py test-ctypes2.py test-ctypes3.py test-ctypes4.py
	
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

ctypes3.py: test-ctypes3.c
	$(H2XML) -I. $< -o $@
	which h2xml.py
	$(XML2PY) -kdst $< -o $@

	
clean:
	rm test-ctypes1 test-ctypes2 test-ctypes3
	rm test-ctypes4
	rm test-ctypes3.py
	



