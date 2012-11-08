#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "whirlpool.h"

int
main(int argc, char *argv[])
{
	struct whirlpool_context ctx;
	const char *msg = "The quick brown fox jumps over the lazy dog";
//	const char *msg = "message digest"; 
//	const char *msg = "";
	unsigned char cp[64];
	unsigned i, n, len;

	whirlpool_context_init(&ctx);

	memset(cp, 0, sizeof(cp));
	n = len = strlen(msg);
	
	whirlpool_update(&ctx, msg, len);
	whirlpool_final(&ctx, cp);

/*	whirlpool_context_init(&ctx);
	for (i = 0; i < 1000000; i++)
		whirlpool_update(&ctx, "a", 1);
	whirlpool_final(&ctx, cp);
*/
	printf("WHIRLPOOL(%s)=\n", msg);
	
	for (i = 0; i < 64; ) {
		printf("\t%02X%02X%02X%02X%02X%02X%02X%02x",
		       cp[i], cp[i+1], cp[i+2], cp[i+3],
		       cp[i+4], cp[i+5], cp[i+6], cp[i+7]);
		i += 8;
		printf("%02X%02X%02X%02X%02X%02X%02X%02x\n",
		       cp[i], cp[i+1], cp[i+2], cp[i+3],
		       cp[i+4], cp[i+5], cp[i+6], cp[i+7]);
		i += 8;
	}

	return 0;	
}

