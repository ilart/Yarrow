#ifndef __FEED_ENTROPY
#define __FEED_ENTROPY

#define ESTIMATE_DIVIDER 2.0

#include "prng.h"

void feed_entropy(int source_id, void *buf, int len, double estimate, struct prng_context *prng);

#endif
