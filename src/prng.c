#include <stdint.h>
#include "prng.h"
#include "hash_desc.h"
#include "cipher_desc.h"
#include "macros.h"
#include "gost.h"
#include "assert.h"
#include "idea.h"

#define INIT(x) ((void * (*)())(x))
#define ENCRYPT(x) ((void (*)(void *, size_t *))(x))
#define DECRYPT(x) ((void (*)(void *, size_t *))(x))
#define FREE_CONTEXT(x) ((void (*)(void * (*)))(x)) 
#define SET_KEY(x) ((void (*)(void *, const size_t *))(x))

struct cipher_desc cipher_desc_tbl[] = {
	{ 
  	  CIPHER_GOST,
 	  GOST_BLOCK_LEN,
	  GOST_KEY_NELEMS,
 	  INIT(gost_context_new),
  	  ENCRYPT(gost_encrypt_32z),
  	  DECRYPT(gost_decrypt_32r),
	  FREE_CONTEXT(gost_context_free),
	  SET_KEY(gost_set_key)
  	},
	{
	  CIPHER_IDEA, 
	  IDEA_BLOCK_NBYTES,
	  IDEA_KEY_NELEMS,
	  INIT(idea_context_new),
	  ENCRYPT(idea_encrypt),
	  DECRYPT(idea_decrypt),
	  FREE_CONTEXT(idea_context_free),
	  SET_KEY(idea_set_key)
	},
/*	{
	  CIPHER_AES_128,
	  AES_BLOCK_LEN,
	  AES_KEY_NELEMS,
	  INIT(aes_context_new),
	  ENCRYPT(aes_encrypt),
	  DECRYPT(aes_decrypt),
	  FREE_CONTEXT(aes_context_free),
	  SET_KEY(aes_set_key_128)
	},
	{
	  CIPHER_AES_192,
	  AES_BLOCK_LEN,
	  AES_KEY_NELEMS,
	  INIT(aes_context_new),
	  ENCRYPT(aes_encrypt),
	  DECRYPT(aes_decrypt),
	  FREE_CONTEXT(aes_context_free),
	  SET_KEY(aes_set_key_192)
	},
	{
	  CIPHER_AES_256,
	  AES_BLOCK_LEN,
	  AES_KEY_NELEMS,
	  INIT(aes_context_new),
	  ENCRYPT(aes_encrypt),
	  DECRYPT(aes_decrypt),
	  FREE_CONTEXT(aes_context_free),
	  SET_KEY(aes_set_key_256)
	},
*/
};

int 
prng_reseed(struct prng_context *prng, const struct entropy_pool *pool)
{
	

	unsigned char *v0, digest[MAX_DIGEST]; 
	unsigned char val[4];
	int i, len;
	u_int32_t tmp[2];

	assert(prng != NULL && pool != NULL);

	v0 = entropy_pool_bytes(pool);
	len = entropy_pool_length(pool);

	printf("len %d\n", len);

	printf(" entropy \n %s \n", v0);
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

	for (i = 2; i <= prng->time_param; i++) {
		prng->hdesc->init(&prng->hash_ctx);
		prng->hdesc->update(&prng->hash_ctx, digest, len);
		prng->hdesc->update(&prng->hash_ctx, v0, len);
		 
		val[0] = (i & 0xff000000) >> 24;
		val[1] = (i & 0xff0000) >> 16;
		val[2] = (i & 0xff00) >> 8;
		val[3] = (i & 0xff);
		prng->hdesc->update(&prng->hash_ctx, val, sizeof(val));
		prng->hdesc->finalize(&prng->hash_ctx, digest);
	}

	printf("digest %s\n", digest);

	prng->hdesc->init(&prng->hash_ctx);
	prng->hdesc->update(&prng->hash_ctx, digest, len);
	prng->hdesc->update(&prng->hash_ctx, prng->key, 32);
	prng->hdesc->finalize(&prng->hash_ctx, digest);
	
	size_adaptor(digest, prng);

	printf("\n key after reseed \n");
	for (i = 0; i < 8; i++) {
		printf(" %u", prng->key[i]);
	}

	printf("\n");

	for (i = 0; i < ARRAY_SIZE(tmp); i++) {
		tmp[i] = 0;
	}

	prng->cipher_ctx = prng->cdesc->context_new();

	prng->cdesc->set_key(prng->cipher_ctx, (u_int32_t *) prng->key);
	prng->cdesc->encrypt(prng->cipher_ctx, tmp);

	for (i = 0; i < ARRAY_SIZE(tmp); i++) {
		prng->counter[i] = tmp[i];
	}

	return TRUE;
}

void prng_encrypt(struct prng_context *prng, void *buf, size_t *size)
{
	int i, cpy_sz; 
	u_int32_t tmp[2];
	char *ptr;
	
	assert(prng != NULL && buf != NULL && size != NULL);

	for (i = 0; i < ARRAY_SIZE(prng->counter); i++ ) {
		tmp[i] = prng->counter[i];
	}

	printf("size in ecrypt %i \n\n",(int) *size);
	ptr = (char *)buf;

	while ((*size) > 0) {
		prng->cdesc->encrypt(prng->cipher_ctx, tmp);
		cpy_sz = (*size < BLOCK_SIZE/8) ? *size : BLOCK_SIZE/8;
		
		memcpy(ptr, tmp, cpy_sz);
		
		prng_next(prng);

		for (i = 0; i < ARRAY_SIZE(prng->counter); i++ ) {
			tmp[i] = prng->counter[i];
		}
		prng->gate_param -= 1;
		if (prng->gate_param == 0)
			prng_generator_gate(prng); 

		*size -= cpy_sz;
		ptr += cpy_sz;
	}
}

void prng_generator_gate(struct prng_context *prng)
{
	int flag;
	char *p;
	size_t key_size = 32;
	
	flag = 0;

	assert(prng != NULL);

	p = (char *) prng->key;
	while (key_size > flag) {
		
		prng->cdesc->encrypt(prng->cipher_ctx, prng->counter);
		memcpy(p + flag, prng->counter, BLOCK_SIZE/8);
		flag += BLOCK_SIZE/8;
		prng_next(prng);
	}
	prng->gate_param = 10;
}

void prng_next(struct prng_context *prng)
{
	int i, tmp;
	unsigned char *c;

	assert(prng != NULL);
	c = prng->counter;

	for (i = 0; i < ARRAY_SIZE(c); i++) {
		tmp = c[i] + 1;
		c[i] = tmp & MASK;

		if (tmp <= UCHAR_MAX)
			break;
	}
}

void 
size_adaptor(unsigned char *digest, struct prng_context *prng)
{
	unsigned char *tmp;
	int i, k, key_len, hash_len;
	char *p;

	key_len = prng->cdesc->key_size;
	hash_len = prng->hdesc->digest_len;

	tmp = calloc(prng->time_param * hash_len, 1);

	p = (char *) prng->key;
	memcpy(tmp, digest, hash_len);	

	for (i = 1; i < prng->time_param; i++) {
		prng->hdesc->init(&prng->hash_ctx);
		for (k = 0; k < i; k++) {
			prng->hdesc->update(&prng->hash_ctx, tmp + k*hash_len, hash_len);
		}
		prng->hdesc->finalize(&prng->hash_ctx, tmp + i*hash_len);
	}

	
	memcpy(p, tmp, key_len);

//	free(tmp);
}

int
prng_set_time_param(struct prng_context *prng, int time_param)
{
	assert(prng != NULL && time_param > 0);

	prng->time_param = time_param;
	
	return 0;
}


int
prng_get_time_param(struct prng_context *prng)
{
	assert(prng != NULL);
	return prng->time_param;
}

int prng_cipher_init(const char *cipher_name, struct prng_context *prng)
{
	printf("cipher = %s\n", cipher_name);
	if((prng->cdesc = cipher_desc_get(cipher_name)))
		return TRUE;
	else 
		return FALSE;
}

int prng_hash_init(const char *hash_name, struct prng_context *prng)
{
	if((prng->hdesc = hash_desc_get(hash_name)))	
		return TRUE;
	else 
		return FALSE;
}

