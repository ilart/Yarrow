CC = gcc
LD = ld
CFLAGS = -Wall -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOUCE=600
#CFLAGS = -Wall -O0 -D_GNU_SOURCE -D_XOPEN_SOURCE=600
#CFLAGS = -Wall -mtune=k8 -march=k8 -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOURCE=600
objects = test.o yarrow.o 
sources = test.c yarrow.c
#headers = yarrow.h  
binaries = test 

.PHONY: clean

all: test yarrow

yarrow.o: yarrow.h

test.o: yarrow.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: test.c test.o
	$(CC) $(CFLAGS) -o $@ $^

yarrow: yarrow.c yarrow.o 
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-rm -rf *~ *.o $(binaries)

