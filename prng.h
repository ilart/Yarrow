#ifndef __PRNG_H
#define __PRNG_H
#define	BLOCK_SIZE	64
#define COUNTER_SIZE	2
#include "hash_desc.h"
#include "prng.h"
#include "entropy_pool.h"
#include "gost.h"

struct prng_context {

	union _hash_ctx hash_ctx;

	int key[8];
	int gate_param;
	int time_param;
	struct gost_context *gost_ctx;
	struct hash_desc *hdesc;
	struct cipher_desc *cdesc;

	u_int32_t counter[COUNTER_SIZE]; /*How big should the buffer? */
};

int prng_reseed(struct prng_context *prng, const struct entropy_pool *pool);

void prng_encrypt(struct prng_context *prng, void *buf, size_t *size);

void prng_generator_gate(struct prng_context *prng);

void prng_next(struct prng_context *prng);

void size_adaptor(unsigned char *digest, struct prng_context *prng);

int prng_set_time_param(struct prng_context *prng, int time_param);

int prng_get_time_param(struct prng_context *prng);
//void feed_entropy(int source_id, void *buf, int len, double estimate, struct entropy_pool *fast_pool, struct entropy_pool *slow_pool, struct prng_context *prng)

#endif

