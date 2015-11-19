# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/ 
DCRYPTINCLUDE = /home/nicolosi/devel/libdcrypt/include/
DCRYPTLIB = /home/nicolosi/devel/libdcrypt/lib/ 
DMALLOC = #-ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# The source file(s) for the each program
all: tst_sha1

tst_sha1.o: tst_sha1.c
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c tst_sha1.c

tst_sha1: tst_sha1.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

clean:
	-rm -f core *.core *.o *~ 

.PHONY: all clean
