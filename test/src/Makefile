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

PY := $(patsubst test-%.32,%_gen.py,$(OBJS32))
#PY64 := $(patsubst %_gen.py,%_gen64.py,$(PY32))

DUMPS32 := $(patsubst %,%.dump,$(OBJS32))
OUTLOGS32 := $(patsubst %,%.stdout,$(OBJS32))
DUMPS64 := $(patsubst %,%.dump,$(OBJS64))
OUTLOGS64 := $(patsubst %,%.stdout,$(OBJS64))

.PHONY: 
	

all: py binaries dumps32 dumps64

binaries: $(OBJS32) $(OBJS64)

#test-ctypes6: test-ctypes6.cpp
#	$(CC) $(CFLAGS) `pkg-config --cflags QtGui` $<  $(LDFLAGS)  -o $@


%.32: %.c
	$(CC) $(CFLAGS) -target linux-i386 $<  $(LDFLAGS)  -o $@

%.64: %.c
	$(CC) $(CFLAGS) -target linux-x86_64 $<  $(LDFLAGS)  -o $@
	
%.32: %.cpp
	$(CXX) $(CPPFLAGS) -target linux-i386 $<  $(LDFLAGS) -L/usr/lib/gcc/i686-linux-gnu/4.8/ -o $@

%.64: %.cpp
	$(CXX) $(CFLAGS) -target linux-x86_64 $<  $(LDFLAGS)  -o $@

#%: %.cpp
#	$(CXX) `pkg-config --libs --cflags QtGui` $(CPPFLAGS) $<  $(LDFLAGS)  -o $@

py: $(PY)

#py64: $(PY64)

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

	
	
cleanall: clean 
	rm -f $(PY) 
	rm -f $(OBJS32) $(OBJS64)

clean: 
	rm -f *~ *.pyc
	rm -f $(OUTLOGS32) $(OUTLOGS64)
	rm -rf $(DUMPS32) $(DUMPS64)


