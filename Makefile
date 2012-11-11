CC = gcc
CFLAGS = -Wall -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOUCE=600
#CFLAGS = -Wall -O0 -D_GNU_SOURCE -D_XOPEN_SOURCE=600
#CFLAGS = -Wall -mtune=k8 -march=k8 -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_XOPEN_SOURCE=600
objects = test.o yarrow.o md5.o 
sources = test.c yarrow.c md5.c
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


#%.o : %.c
#	$(CC) $(CFLAGS) -c -o $@ $<

#test: test.c test.o
#	$(CC) $(CFLAGS) -c -o $@ $<

#yarrow.o: yarrow.c  
#	$(CC) $(CFLAGS) -o $@ $<

clean:
	-rm -rf *~ *.o $(binaries)

