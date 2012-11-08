CC = gcc
LD = ld
CFLAGS = -Wall -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOUCE=600
#CFLAGS = -Wall -O0 -D_GNU_SOURCE -D_XOPEN_SOURCE=600
#CFLAGS = -Wall -mtune=k8 -march=k8 -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOURCE=600
objects = test.o md5.o 
sources = test.c ./hash/md5.c
headers = yarrow.h ./hash/md5.h 
binaries = test md5-test

.PHONY: clean

all: test md5-test 

md5.o: ./hash/md5.h

test.o: yarrow.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: test.c test.o
	$(CC) $(CFLAGS) -o $@ $^

md5-test: ./hash/md5.c md5.o 
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-rm -rf *~ *.o $(binaries)

