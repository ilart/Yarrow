
int add_to_fast[MAXSOURCES];

void
feed_entropy(int source_id, void *buf, int len, double estimate)
{
	int add_to_fast;

	add_to_fast = add_to_fast[source_id] = !add_to_fast[source_id];

	if (add_to_fast) {
		entropy_pool_add(fast_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(fast_pool)) {
			reseed_prng();
			entropy_pool_clean(fast_pool);
	}
	} else {
		entropy_pool_add(slow_pool, source_id, buf, len, estimate);
		if (entropy_pool_is_thresholded(slow_pool)) {
		entropy_pool_feed_to(fast_pool, slow_pool);
		reseed_prng();
		entropy_pool_clean(fast_pool);
		entropy_pool_clean(slow_pool);
		}
	}
}


