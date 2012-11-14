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
	const char buf[] = "qw qw as zx zx zz zz 11";
	const char tmp_buf[16];

	res = entropy_pool_init(&fast_pool, 17, HASH_SHA256);
	if (res == 0)
		printf("pool.nsources %d "
		       "pool.k %d "
		       "pool.hdesc->name %s \n",
		       fast_pool.nsources, 
		       fast_pool.k, 
		       fast_pool.hdesc->name);

	res = entropy_pool_init(&slow_pool, 12, HASH_SHA256);
	if (res == 0)
		printf("slow_pool.nsoursec  %d"
		       "slow_pool.k %d" 
		       "slow_pool.hdesc->k %s \n", 
		       slow_pool.nsources, 
		       slow_pool.k, 
		       slow_pool.hdesc->name);

	res = entropy_pool_set_k(&slow_pool, 2);
	if (res == 0)
		printf("entropy_pool_set_k %d\n", slow_pool.k);

	res = entropy_pool_get_k(&slow_pool);
	if (res != 0)
                printf("entropy_pool_get_k %d\n", res);
	
	res = entropy_pool_add(&slow_pool, 0, buf, 10, 0.3);
	if (res == 0)
		printf("pool.estimate add %f \n", 
			slow_pool.estimate[0]);
	else {
		printf("error of entropy_pool_add");
		return EPOOL_FAIL;
	}
	
	slow_pool.hdesc->finalize(&slow_pool, (void *)tmp_buf);
	printf("hash = %s \n", tmp_buf);

	res = entropy_pool_is_thresholded(&fast_pool);
	printf("thresholded = %d \n", res);
	
	//entropy_pool_feed_to(&fast_pool, &slow_pool);

	/* how see result, current hash? */		
	
	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p,"
			"pool.nsources %d "
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);

	return 0;
}
