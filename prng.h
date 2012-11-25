#ifndef __PRNG_H
#define __PRNG_H

struct prng reseed_prng(struct entropy_pool *pool, struct prng *prng_ptr, u_int16_t);

struct prng {
	int key;
	int counter;
};

#endif
