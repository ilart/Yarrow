#include <stdint.h>
#include "prng.h"
#include "hash_desc.h"
#include "macros.h"
/*int
prng_init(struct prng_context *prng, const char *cipher_name, const char *hash_name)
{
	hdesc = hash_desc_get(hash_name);
	
	prng->hdesc = hash_desc_get(hash_name);
	prng->cipher_ctx = cipher_desc_get(cipher_name);

}
*/
int 
prng_reseed(struct prng_context *prng, const struct entropy_pool *pool, int param)
{
	unsigned char v0, digest[MAXDIGEST]; 
	unsigned char val[4];
	int i, key; 
	int len;
	struct gost_context *gost_ctx;

	v0 = entropy_pool_bytes(pool);
	len = entropy_pool_length(pool);

	get_hash_desc();

	prng->hdesc->init(&prng->hash_ctx);	
	prng->hdesc->update(&prng->hash_ctx, v0, len);
	prng->hdesc->update(&prng->hash_ctx, v0, len);
	i = 1;
	val[0] = (i & 0xff000000) >> 24;
	val[1] = (i & 0xff0000) >> 16;
	val[2] = (i & 0xff00) >> 8;
	val[3] = (i & 0xff);

	prng->hdesc->update(&prng->hash_ctx, val, sizeof(val));
	prng->hdesc->finalize(&prng->hash_ctx, digest);

	for (i = 2; i <= param; i++) {
		prng->hdesc->init(&prng->hash_ctx);
		prng->hdesc->update(&prng->hash_ctx, digest, len);
		prng->hdesc->update(&prng->hash_ctx, val, len);
		 
		val[0] = (i & 0xff000000) >> 24;
		val[1] = (i & 0xff0000) >> 16;
		val[2] = (i & 0xff00) >> 8;
		val[3] = (i & 0xff);
		prng->hdesc->update(&prng->hash_ctx, val, sizeof(val));
		prng->hdesc->finalize(&prng->hash_ctx, digest);
	}
	
	for (i = 0; i < ARRAY_SIZE(prng->counter); i++){
		prng->counter[i] = 0;			
	}
	
	gost_ctx = gost_context_new();
	gost_set_key(gost_ctx, );
	gost_encrypt_32z(prng->gost_ctx, prng->counter);
}
/*
void
prng_set_parameter(int param);

void prng_encrypt(struct prng_context *prng, void *buf, size_t *size)
{
	int tmp[MAXHASH_SIZE], cpy_sz;
	char *ptr;
	
	assert(prng != NULL && buf != NULL && size != NULL);

	memcpy(tmp, prng->counter, sizeof(prng->counter));
	ptr = (char *)buf;

	while (size != 0){
		gost_encrypt(prng->gost_ctx, tmp);
		*size<BLOCK_SIZE ? cpy_sz=*size : cpy_sz=BLOCK_SIZE;
		
		memcpy(ptr, tmp, cpy_sz);
		prng_next(prng);			

		if (prng->parma == 0)
			prng_generator_gate(prng); 

		*size -= cpy_sz;
	}
}

void prng_next(struct prng_context *prng)
{
	
}
void prng_generator_gate(struct prng_context *prng)
{
	int key, tmp_counter[MAXBLOCK_SIZE];

	tmp_counter = prng->counter;
	gost_ecrypt_32z(prng, tmp_counter);
	//prng->cdesc->key_size
}

void prng_deinit(struct prng_context *prng);
*/
