#ifndef __PRNG_H
#define __PRNG_H
#define	MAXBLOCK_SIZE	64

struct prng_context {

	union _hash_ctx hash_ctx;
	int parma;
	struct hash_desc *hdesc;
	struct cipher_desc *cdesc;

	int counter[MAXBLOCK_SIZE / 8 / 4];
};

int prng_reseed(struct prng_context *prng, const struct entropy_pool *pool, int param);
#endif
