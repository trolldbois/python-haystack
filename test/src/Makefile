#!/usr/bin/make -f

LDFLAGS = -ldl
INCLS = 

EXTRA =

CFLAGS = -O2 -g -Wall $(INCLS) $(EXTRA)
CPPFLAGS = -O2 -g -Wall -stdlib=libstdc++ -x c++
CC=clang
CXX=clang++

pid=

C2PY=clang2py

SRCS := $(wildcard *.c *.cpp) 
OBJS32 := $(patsubst %.c,%.32,$(SRCS))
OBJS32 := $(patsubst %.cpp,%.32,$(OBJS32))
OBJS64 := $(patsubst %.32,%.64,$(OBJS32))

DUMPS32 := $(patsubst %,%.dump,$(OBJS32))
OUTLOGS32 := $(patsubst %,%.stdout,$(OBJS))
PY32 := $(patsubst test-%,%_gen.py,$(OBJS))
DUMPS64 := $(patsubst %.32,%.64,$(DUMPS32))
OUTLOGS64 := $(patsubst %.32,%.64,$(OUTLOGS32))
PY64 := $(patsubst %.32,%.64,$(PY32))

.PHONY: 
	

all: py32 py64 binaries dumps32 dumps64

binaries: $(OBJS32) $(OBJS64)

#test-ctypes6: test-ctypes6.cpp
#	$(CC) $(CFLAGS) `pkg-config --cflags QtGui` $<  $(LDFLAGS)  -o $@


%.32: %.c
	$(CC) $(CFLAGS) -triple linux-i386 $<  $(LDFLAGS)  -o $@

%.64: %.c
	$(CC) $(CFLAGS) -triple linux-x86_64 $<  $(LDFLAGS)  -o $@
	
%.32: %.cpp
	$(CXX) $(CPPFLAGS) -triple linux-i386 $<  $(LDFLAGS)  -o $@

%.64: %.cpp
	$(CXX) $(CFLAGS) -triple linux-x86_64 $<  $(LDFLAGS)  -o $@

#%: %.cpp
#	$(CXX) `pkg-config --libs --cflags QtGui` $(CPPFLAGS) $<  $(LDFLAGS)  -o $@

py32: $(PY32)

py64: $(PY64)

%_gen.py: test-%.c 
	$(C2PY) -k dst $< -o $@

%_gen.py: test-%.cpp 
	$(C2PY) -k dst $< -o $@


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

	
	
clean: 
	rm -f *~ *.pyc
	rm -f $(OBJS32) $(OBJS64)
	rm -f $(OUTLOGS32) $(OUTLOGS64)
	rm -f $(PY32) $(PY64)
	rm -rf $(DUMPS32) $(DUMPS64)


