#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> 
#include "yarrow.h"
#include "entropy_pool.h"
#include "hash_desc.h"
#include "macros.h"
#include "prng.h"
#include "gost.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"
#include "feed_entropy.h"

int main(int argc, char **argv)
{
	int res, i, fd;
//int add_to_fast[MAXSOURCES];
	size_t size = 510;
	int buf_random[512];
	double tmp;
	struct entropy_pool fast_pool, slow_pool;
	struct prng_context prng;
//	struct gost_context *gost_ctx;
	const char buf[] = "22 333 44 11 aa bb qw qw as zx zx zz zz 11";
	//char tmp_buf[16];
	unsigned char *tmp_s;

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
		       "slow_pool.hdesc->name %s \n", 
		       slow_pool.nsources, 
		       slow_pool.k, 
		       slow_pool.hdesc->name);
	printf("\n");
	
	res = entropy_pool_length(&slow_pool);
	printf("entropy_pool_lenght %u \n", res);

	res = entropy_pool_set_nsources(&fast_pool, 15);
	if (res == 0)
	        printf("entropy_pool_set_nsources %d\n", fast_pool.nsources);

	res = entropy_pool_get_nsources(&fast_pool);
	if (res != 0)
                printf("\n entropy_pool_get_nsources %d\n", res);
	printf("\n");
	
	res = entropy_pool_set_k(&fast_pool, 2);
	if (res == 0)
		printf("entropy_pool_set_k %d\n", fast_pool.k);

	res = entropy_pool_get_k(&fast_pool);
	if (res != 0)
                printf("entropy_pool_get_k %d\n", res);
	printf("\n");

	res = entropy_pool_set_threshold(&fast_pool, 0, 121.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in fast %f\n", fast_pool.threshold[0]);

	res = entropy_pool_set_threshold(&slow_pool, 0, 51.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in slow %f\n", slow_pool.threshold[0]);
	
	
	tmp = entropy_pool_get_threshold(&fast_pool, 0);	
	if (tmp != 0)
                printf("entropy_pool_get_threshold %f\n", tmp);
	printf("\n");

	feed_entropy(0, buf, 33, 0.5, fast_pool, slow_pool, prng);

/*	res = entropy_pool_add(&fast_pool, 0, buf, 33, 0.5);
	if (res == 0)
		printf("pool.estimate add %f \n", 
			fast_pool.estimate[0]);
	else {
		printf("error of entropy_pool_add");
		return EPOOL_FAIL;
	}
	printf("\n");
*/	
	//______________________________PRNG___________________
	//

	
	fd = open("/dev/urandom" , O_RDONLY);
	if (fd == -1)
		perror("Error of open");

	res = read(fd, &prng.key, sizeof(prng.key));
	if (res == -1)
		perror("Error of write");

	printf("key before reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n");

//	res = entropy_pool_get_nsources(&fast_pool);

	prng.param = 9;

//	gost_ctx = gost_context_new();
	prng_reseed(&prng, &fast_pool, 10);
	printf("debug of prng, prng->hdesc %p, prng->gost_ctx %p, \n", prng.hdesc, prng.gost_ctx);

/*	printf("\n key after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n counter after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.counter); i++) {
		printf("%u ", prng.counter[i]);
	}
*/
	prng_encrypt(&prng, buf_random, &size);	
	printf("\nrandom values\n");
	for (i = 0; i < 510/4; i++) {
		printf(" %d, ", buf_random[i]);
	}

//_______________END PRNG____________________
//
	res = entropy_pool_is_thresholded(&fast_pool);
	printf("thresholded = %d \n", res);

	printf("digest_len %d\n", fast_pool.hdesc->digest_len);	
	
	entropy_pool_feed_to(&slow_pool, &fast_pool);
	printf("feed: buffer = %s\n", fast_pool.buffer);
	/* how see result, current hash? */		
	
	tmp_s = entropy_pool_bytes(&slow_pool);
	printf("slow_pool_byts %s \n", tmp_s);

	entropy_pool_clean(&fast_pool);
	printf("entropy_pool_clean %s", fast_pool.buffer);


//	slow_pool.hdesc->finalize(&slow_pool, (void *)tmp_buf);
//	printf("hash = %s \n", tmp_buf);
	
	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p,"
			"pool.nsources %d "
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);


	close(fd);

	return 0;
}
