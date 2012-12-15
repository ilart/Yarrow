#ifndef __PRNG_H
#define __PRNG_H
#define	MAXBLOCK_SIZE	64

struct prng reseed_prng(struct entropy_pool *pool, struct prng *prng_ptr, u_int16_t);

struct prng_context {

	int parma;
	struct hash_desc *hdesc;
	struct cipher_desc *cdesc;

	int counter[MAXBLOCK_SIZE / 8 / 4];
};

#endif
