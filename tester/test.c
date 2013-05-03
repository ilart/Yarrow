#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

int
main (int argc, char **argv)
{
	int i, base, t, d, r, val;
	char str[10];

	bzero(str, sizeof(str));
	val = atoi(argv[1]);
	base = 16;
	d = val;
	r = 1;
	for (i = 0; r != 0; i++) {
		r = d / base;
		t = d % base;
		printf("r = %d, t = %d\n", r,t);
		
		if (t < 10)
			str[i] = t + '0';
		else
			str[i] = t - 10 + 'a';

	
		printf("%c ", str[i]);
		d = r;
	} 
	printf( "val %d = %s\n", val, str);
	return 0;
}


