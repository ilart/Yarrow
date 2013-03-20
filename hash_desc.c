#include "hash_desc.h"
#include <stdio.h>


struct hash_desc *
hash_desc_get(const char *hash_name)
{
	int i;

	extern struct hash_desc hash_desc_tbl[3];
	assert(hash_name != 0);
	
	for ( i = 0; i < ARRAY_SIZE(hash_desc_tbl); i++ ) {
		if (strcmp(hash_name, hash_desc_tbl[i].name) == 0) {
			return &hash_desc_tbl[i];
		}
	}

	return FALSE;
}

