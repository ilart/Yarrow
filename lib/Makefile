CC = gcc
CFLAGS = -Wall -O2 -fomit-frame-pointer -ggdb -D_GNU_SOURCE -D_XOPEN_SOUCE=600
objects = md5.o sha1.o sha256.o gost.o idea.o 

INLUDES = -I ../include 

crypto = crypto.a

.PHONY: clean

all: $(crypto)

$(crypto): $(objects) 
	ar -r $@ $^

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $^ -o $@

clean:
	rm -rf *~ *.o $(crypto)
