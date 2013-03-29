CC = gcc
CFLAGS = -Wall -O2 -fomit-frame-pointer -ggdb -D_GNU_SOURCE -D_XOPEN_SOUCE=600
objects = yarrow_init.o yarrow.o feed_entropy.o prng.o cipher_desc.o hash_desc.o
VPATH = ./src
INCLUDES = -I ./include/ -I ./lib/  
binaries = yarrow_init 
crypto = ./lib/crypto.a

.PHONY: clean

all: $(binaries)  

$(binaries): $(objects) $(crypto)
	$(CC) $(CFLAGS) -o $@ $^

yarrow_init.o: yarrow_init.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(crypto):
	make -C ./lib/

yarrow.o: yarrow.c 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

feed_entropy.o: feed_entropy.c 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<
		
prng.o: prng.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

cipher_desc.o: cipher_desc.c 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

hash_desc.o: hash_desc.c 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	-rm -rf *~ *.o $(binaries)
	make -C ./lib/ clean

