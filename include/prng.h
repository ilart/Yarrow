#ifndef __PRNG_H
#define __PRNG_H

#define	BLOCK_SIZE	64

#define COUNTER_SIZE	2

#define MIN_TIME_PARAM 2 

#include "hash_desc.h"

#include "entropy_pool.h"

#include "cipher_desc.h"

#include "gost.h"

//#include "idea.h"

struct prng_context {

	union _cipher_ctx *cipher_ctx;

	int key[8];
	
	int gate_param;
	
	int time_param;
	
	struct hash_desc *hdesc;
	
	struct cipher_desc *cdesc;

	union _hash_ctx hash_ctx;
	u_int32_t counter[COUNTER_SIZE]; 

	char random_storage[512];
};

int prng_reseed(struct prng_context *prng, const struct entropy_pool *pool);

void prng_encrypt(struct prng_context *prng, void *buf, size_t *size);

void prng_generator_gate(struct prng_context *prng);

void prng_next(struct prng_context *prng);

void size_adaptor(unsigned char *digest, struct prng_context *prng);

int prng_set_time_param(struct prng_context *prng, int time_param);

int prng_get_time_param(struct prng_context *prng);

int prng_cipher_init(const char *cipher_name, struct prng_context *prng);

int prng_hash_init(const char *hash_name, struct prng_context *prng);

//void feed_entropy(int source_id, void *buf, int len, double estimate, struct entropy_pool *fast_pool, struct entropy_pool *slow_pool, struct prng_context *prng)

#endif

