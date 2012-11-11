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
	int res;
	struct entropy_pool fast_pool, slow_pool;

	res = entropy_pool_init(&fast_pool, 12, HASH_MD5);
	if (res == 0)
	printf("test entropy_pool_init %d "
	       "pool->nsources %d "
	       "pool->k %d "
	       "pool->hdesc.init %s "
	       "pool->hdesc.update %s "
	       "pool.hdesc->name %s \n",
	       res, fast_pool.nsources, fast_pool.k, (char *)fast_pool.hdesc->init, (char *)fast_pool.hdesc->update, fast_pool.hdesc->name );

//	fast_pool.hdesc->init();
//	fast_pool()
	return 0;
}
