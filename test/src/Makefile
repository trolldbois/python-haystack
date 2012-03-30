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
OUTLOGS := $(patsubst %,%.stdout,$(OBJS))
PY := $(patsubst test-%,%.py,$(OBJS))

.PHONY: 
	
#py
all: binaries dumps 

binaries: $(OBJS)

%: %.c
	$(CC) $(CFLAGS) $<  $(LDFLAGS)  -o $@
	
%: %.cpp
	$(CXX) $(CPPFLAGS) $<  $(LDFLAGS)  -o $@


#py: $(PY)
#
#%.xml: test-%.c
#	$(H2XML) -I. $< -o $@
#
#%.xml: test-%.cpp
#	$(H2XML) -I. $< -o $@
#
#%.py: %.xml
#	$(XML2PY) -kdst $< -o $@


dumps: $(SRCS) $(DUMPS) $(OBJS) 
	
%.dump: %.c 
	sudo python make.py $@
	sudo chown -R jal.jal $@
	
%.dump: %.cpp
	sudo python make.py $@
	sudo chown -R jal.jal $@

	
	
clean: 
	rm -f *~ *.pyc
	rm -f $(OBJS)
	rm -f $(OUTLOGS)
	rm -f $(PY)
	rm -rf $(DUMPS)


