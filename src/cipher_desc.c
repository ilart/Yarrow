#include "cipher_desc.h"
#include <stdio.h>

struct cipher_desc *
cipher_desc_get(const char *cipher_name)
{
	int i;

	extern struct cipher_desc cipher_desc_tbl[2];
	assert(cipher_name != 0);
	
	for ( i = 0; i < ARRAY_SIZE(cipher_desc_tbl); i++ ) {
		printf("i = %d\n cipher_name = %s \n", i, cipher_desc_tbl[i].name);
		if (strcmp(cipher_name, cipher_desc_tbl[i].name) == 0) {
			printf("if\n");
			return &cipher_desc_tbl[i];
		}
	}

	return FALSE;
}
 

