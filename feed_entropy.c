#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"
#include "feed_entropy.h"
#include "entropy_pool.h"
int add_to_fast[MAXSOURCES];
void
feed_entropy(int source_id, void *buf, int len, double estimate, struct entropy_pool *fast_pool, struct entropy_pool *slow_pool, struct prng_context *prng, int param)
{
	int add;

	add = add_to_fast[source_id] = !add_to_fast[source_id];

	if (add) {
		entropy_pool_add(fast_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(fast_pool)) {
			prng_reseed(prng, fast_pool, param);
			entropy_pool_clean(fast_pool);
		}
	} else {
		entropy_pool_add(slow_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(slow_pool)) {
			entropy_pool_feed_to(fast_pool, slow_pool);
			prng_reseed(prng, slow_pool, param);
			entropy_pool_clean(fast_pool);
			entropy_pool_clean(slow_pool);
		}
	}
}


