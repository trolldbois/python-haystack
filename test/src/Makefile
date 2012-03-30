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

SRCS := $(wildcard *.c *.cpp) 
OBJS := $(patsubst %.c,%,$(SRCS))
OBJS := $(patsubst %.cpp,%,$(OBJS))

DUMPS := $(patsubst %,%.dump,$(OBJS))
OUTLOGS := $(patsubst %,%.out,$(OBJS))
PY := $(patsubst test-%,%.py,$(OBJS))

.PHONY: 
	
all: binaries dumps

binaries: $(OBJS)

py: $(PY)
	
%.dump: %.c 
	sudo python make.py $@
	sudo chown -R jal.jal $@
	
%.dump: %.cpp
	sudo python make.py $@
	sudo chown -R jal.jal $@

dumps: $(SRCS) $(DUMPS) $(OBJS) 
	
%: %.c
	$(CC) $(CFLAGS) $<  $(LDFLAGS)  -o $@
	
%: %.cpp
	$(CXX) $(CPPFLAGS) $<  $(LDFLAGS)  -o $@

%.xml: test-%.c
	$(H2XML) -I. $< -o $@

%.xml: test-%.cpp
	$(H2XML) -I. $< -o $@

%.py: %.xml
	$(XML2PY) -kdst $< -o $@

	
clean: cleandump
	rm -f $(OBJS)
	rm -f $(OUTLOGS)
	rm -f $(PY)
	
cleandump:
	rm -rf $(DUMPS)


