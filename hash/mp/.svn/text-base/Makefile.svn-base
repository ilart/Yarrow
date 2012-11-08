CC = gcc
LD = ld
CFLAGS = -g -Wall -fPIC -O2 -D_GNU_SOURCE -D_XOPEN_SOURCE=600
SOURCES = rsa.c sha1.c sha256.c emeoaep.c
OBJECTS = $(MP_OBJECTS) rsa.o sha1.o sha256.o emeoaep.o
HEADERS = $(MP_HEADERS) rsa.h sha1.h sha256.h emeoaep.h
BINARIES = test

MP_OBJECTS = mp_util.o mp_copy.o mp_ensure.o mp_add.o \
	     mp_sub.o mp_cmp.o mp_shift.o mp_mul.o mp_sqr.o \
	     mp_reduce.o mp_div.o mp_random.o mp_primality.o \
	     mp_gcd.o mp_mod_inv.o mp_mod_exp.o mp_init.o \
	     mp_clear.o mp_set.o mp_uchar.o

MP_SOURCES = mp_util.c mp_copy.c mp_ensure.c mp_add.c \
	     mp_sub.c mp_cmp.c mp_shift.c mp_mul.c mp_sqr.c \
	     mp_reduce.c mp_div.c mp_random.c mp_primality.c \
	     mp_gcd.c mp_mod_inv.c mp_mod_exp.c mp_init.c \
	     mp_clear.c mp_set.c mp_uchar.c

MP_HEADERS = mp.h mp_common.h

# Cryptographic primitives.

all: test

sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c -o $@ $<

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

emeoaep.o: emeoaep.c emeoaep.h sha256.o sha1.o
	$(CC) $(CFLAGS) -c -o $@ $<

rsa.o: rsa.c rsa.h mp.h
	$(CC) $(CFLAGS) -c -o $@ $<

#
# Multiple Precision Integer library objects.
#

mp_util.o: mp_util.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_ensure.o: mp_ensure.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_copy.o: mp_copy.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_add.o: mp_add.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_sub.o: mp_sub.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_cmp.o: mp_cmp.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_shift.o: mp_shift.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_mul.o: mp_mul.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_sqr.o: mp_sqr.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_reduce.o: mp_reduce.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_div.o: mp_div.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_random.o: mp_random.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_primality.o: mp_primality.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_gcd.o: mp_gcd.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_mod_inv.o: mp_mod_inv.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_mod_exp.o: mp_mod_exp.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_init.o: mp_init.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_clear.o: mp_clear.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_set.o: mp_set.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

mp_uchar.o: mp_uchar.c $(MP_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

#######
# Unix shared libraries.
#######

.PHONY: lib clean

lib: libmp.so.1.0

libmp.so.1.0: $(MP_HEADERS) $(MP_OBJECTS)
	$(CC) -shared -Wl,--version-script=libmp.ver,-soname,libmp.so.1 \
	      -o libmp.so.1.0 $(MP_OBJECTS)
	-ln -s libmp.so.1.0 libmp.so.1
	-ln -s libmp.so.1 libmp.so

#######

test: test.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ test.c $(OBJECTS) 

clean:
	-rm -rf $(OBJECTS) $(BINARIES) libmp.so libmp.so.1 libmp.so.1.0

