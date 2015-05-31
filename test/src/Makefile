#!/usr/bin/make -f

LDFLAGS = -ldl
INCLS = 

EXTRA =

CFLAGS = -O2 -g -Wall $(INCLS) $(EXTRA)
CPPFLAGS = -O2 -g -Wall -stdlib=libstdc++ -x c++
CC=clang
CXX=clang++

TGT32=i386-linux
TGT64=x86_64-linux

pid=

C2PY=clang2py

SRCS := $(wildcard *.c *.cpp) 
OBJS32 := $(patsubst %.c,%.32,$(SRCS))
OBJS32 := $(patsubst %.cpp,%.32,$(OBJS32))
OBJS64 := $(patsubst %.32,%.64,$(OBJS32))

PY32 := $(patsubst test-%.32,%_gen32.py,$(OBJS32))
PY64 := $(patsubst test-%.64,%_gen64.py,$(OBJS64))

DUMPS32 := $(patsubst %,%.dump,$(OBJS32))
OUTLOGS32 := $(patsubst %,%.stdout,$(OBJS32))
DUMPS64 := $(patsubst %,%.dump,$(OBJS64))
OUTLOGS64 := $(patsubst %,%.stdout,$(OBJS64))

.PHONY: 
	

all: py binaries dumps

binaries: $(OBJS32) $(OBJS64)

dumps: dumps32 dumps64

%.32: %.c
	$(CC) $(CFLAGS) -target $(TGT32) $<  $(LDFLAGS)  -o $@

%.64: %.c
	$(CC) $(CFLAGS) -target $(TGT64) $<  $(LDFLAGS)  -o $@
	
%.32: %.cpp
	$(CXX) $(CPPFLAGS) -target $(TGT32) $<  $(LDFLAGS) -L/usr/lib/gcc/i686-linux-gnu/4.8/ -o $@

%.64: %.cpp
	$(CXX) $(CFLAGS) -target $(TGT64) $<  $(LDFLAGS)  -o $@

py: $(PY32) $(PY64)

%_gen32.py: test-%.c 
	$(C2PY) -k dstu -x $< -o $@ --target $(TGT32)

%_gen32.py: test-%.cpp 
	$(C2PY) -k dstu -x $< -o $@ --target $(TGT32)

%_gen64.py: test-%.c 
	$(C2PY) -k dstu -x $< -o $@ --target $(TGT64)

%_gen64.py: test-%.cpp 
	$(C2PY) -k dstu -x $< -o $@ --target $(TGT64)


dumps32: $(SRCS) $(DUMPS32) $(OBJS32) 

dumps64: $(SRCS) $(DUMPS64) $(OBJS64) 
	
%.32.dump: %.c 
	sudo python make.py $@
	sudo chown -R jal.jal $@

%.32.dump: %.cpp
	sudo python make.py $@
	sudo chown -R jal.jal $@
	
%.64.dump: %.c 
	sudo python make.py $@
	sudo chown -R jal.jal $@
	
%.64.dump: %.cpp
	sudo python make.py $@
	sudo chown -R jal.jal $@

	
cleanpy: 
	rm -f $(PY32) $(PY64) 
	
cleanall: clean cleanpy 
	rm -f $(OBJS32) $(OBJS64)
	rm -f $(OUTLOGS32) $(OUTLOGS64)
	rm -rf $(DUMPS32) $(DUMPS64)

clean: 
	rm -f *~ *.pyc


