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
	const char buf[] = "qqqwwwmmm";

	res = entropy_pool_init(&fast_pool, 12, HASH_MD5);
	if (res == 0)
	printf("test entropy_pool_init %d "
	       "pool->nsources %d "
	       "pool->k %d "
	       "pool->hdesc.init %s "
	       "pool->hdesc.update %s "
	       "pool.hdesc->name %s \n",
	       res, 
	       fast_pool.nsources, 
	       fast_pool.k, 
	       (char *)fast_pool.hdesc->init, 
	       (char *)fast_pool.hdesc->update, 
	       fast_pool.hdesc->name );

	res = entropy_pool_add(&fast_pool, 0, buf, 10, 0.3);
	if (res == 0)
		printf("pool.estimate[source_id] = %f \n", 
			fast_pool.estimate[0]);
	res = entropy_pool_is_thresholded(&fast_pool);
	printf("thresholded = %d \n", res);
	return 0;
}
