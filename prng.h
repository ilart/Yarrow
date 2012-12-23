#include "hash_desc.h"
#include "gost.h"
#ifndef __PRNG_H
#define __PRNG_H
#define	BLOCK_SIZE	64
#define COUNTER_SIZE	2

struct prng_context {

	union _hash_ctx hash_ctx;

	u_int32_t key[MAXDIGEST / 4];
	int param;
	struct gost_context *gost_ctx;
	struct hash_desc *hdesc;
	struct cipher_desc *cdesc;

	int counter[COUNTER_SIZE]; /*How big should the buffer? */
};

int prng_reseed(struct prng_context *prng, const struct entropy_pool *pool, int param);

void prng_encrypt(struct prng_context *prng, void *buf, size_t *size);

void prng_generator_gate(struct prng_context *prng);

#endif

