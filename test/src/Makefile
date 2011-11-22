#!/usr/bin/make -f

CPPFLAGS = -O2 -g -Wall
LIBS = 
INCLS = 

EXTRA =

FLAGS= ${INCLS} ${EXTRA}



.PHONY:
	


.c.test:
	gcc ${FLAGS} ${LIBS} $(.SOURCE) -o $(.TARGET)
	
.cpp.test: 
	g++ ${FLAGS} ${LIBS} $(.SOURCE) -o $(.TARGET)




