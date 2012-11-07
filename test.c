#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> 
#include "yarrow.h"
#include "entropy_pool.h"
#include "hash_desc.h"

int main(int argc, char **argv)
{
	
	int i;
	struct entropy_pool fast_pool, slow_pool;

	i = entropy_pool_init(fast_pool, 12, HASH_SHA1);
	printf("test entropy_pool_init %d \
		       	pool->nsources %d \
			pool->k	%d \
			\n", i, fast_pool.nsources, fast_pool.k );
return 0;
}
