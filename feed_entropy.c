#include "common.h"
#include "entropy_pool.h"
#include "feed_entropy.h"

void
feed_entropy(int source_id, void *buf, int len, double estimate, struct prng_context *prng)
{
	int add;
	extern struct entropy_pool fast_pool, slow_pool;  
	extern add_to_fast[MAXSOURCES];
	add = add_to_fast[source_id] = !add_to_fast[source_id];

	printf("\nadd= %d\n", add);
	if (add) {
		entropy_pool_add(&fast_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(&fast_pool)) {
			printf("THRESHOLDED FAST!!!\n");
			prng_reseed(prng, &fast_pool);
			entropy_pool_clean(&fast_pool);
		}
	} else {
		entropy_pool_add(&slow_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(&slow_pool)) {
			printf("THRESHOLDED SLOW!!!\n");
			entropy_pool_feed_to(&fast_pool, &slow_pool);
			prng_reseed(prng, &slow_pool);
			entropy_pool_clean(&fast_pool);
			entropy_pool_clean(&slow_pool);
		}
	}
}


