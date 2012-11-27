#ifndef __PRNG_H
#define __PRNG_H

struct prng reseed_prng(struct entropy_pool *pool, struct prng *prng_ptr, u_int16_t);

struct prng {
	union _encrypt_ctx {
		struct gost_context gost_ctx;
		struct aes_context aes_ctx;
	} encrypt_ctx;
	int counter;
};

#endif
