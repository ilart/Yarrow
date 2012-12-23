CC = gcc
CFLAGS = -Wall -O2 -fomit-frame-pointer -ggdb -D_GNU_SOURCE -D_XOPEN_SOUCE=600
#CFLAGS = -Wall -O0 -D_GNU_SOURCE -D_XOPEN_SOURCE=600
#CFLAGS = -Wall -mtune=k8 -march=k8 -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOURCE=600
objects = test.o yarrow.o md5.o sha1.o sha256.o gost.o
sources = test.c yarrow.c md5.c sha1.c sha256.c gost.c
#headers = yarrow.h  
binaries = test 

.PHONY: clean

all: test  

test: $(objects)
	$(CC) $(CFLAGS) -o $@ $^

yarrow.o: yarrow.c entropy_pool.h hash_desc.h
	$(CC) $(CFLAGS) -c -o $@ $<

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c -o $@ $<

sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c -o $@ $<

sha256.o: sha256.c sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

#prng.o: prng.c prng.h hash_desc.h
#	$(CC) $(CFLAGS) -c -o $@ $<
		
gost.o: gost.c gost.h macros.h common.h 
	$(CC) $(CFLAGS) -c -o $@ $<
	
#%.o : %.c
#	$(CC) $(CFLAGS) -c -o $@ $<

#test: test.c test.o
#	$(CC) $(CFLAGS) -c -o $@ $<

#yarrow.o: yarrow.c  
#	$(CC) $(CFLAGS) -o $@ $<

clean:
	-rm -rf *~ *.o $(binaries)

