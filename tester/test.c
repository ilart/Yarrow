#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main (int argc, char **argv)
{
	int i, left, fd;
	int r;
	unsigned char str[40], res[70];

	fd = open("/dev/random", O_RDONLY);
	bzero(str, sizeof(str));
	memset(res, 1, sizeof(res));

	left = 32;

	while (left) {
		left -= read(fd, str+32-left, left);
	}
	printf("str %s\n", str);
	for (i = 0; i < 32; i++) {
		r = (int ) str[i];
		printf("%d ", str[i]);
		if (r < 16 && r > 0) 
			sprintf(res+i*2, "0%x",str[i]);
		else 
			sprintf(res+i*2, "%x", str[i]);
	}

	printf("\n");
 
	for (i = 0; i < 64; i++)
		printf( "%c", res[i]);
	close(fd);
	return 0;
}


