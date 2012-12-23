#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include "yarrow.h"
#include "macros.h"
#include "gost.h"
#include "hash_desc.h"
#define DEFAULT_K 3
#define BUFFER_SZ 64

#define HASH_INIT(x) ((void (*)(void *))(x))
#define HASH_UPDATE(x) ((void (*)(void *, const void *, size_t))(x))
#define HASH_FINAL(x) ((void * (*)(void *, unsigned char *))(x))

struct hash_desc desc_tbl[] = {
	{ 
	  HASH_MD5,
	  MD5_DIGEST_LEN, 
	  HASH_INIT(md5_context_init),
	  HASH_UPDATE(md5_update),
	  HASH_FINAL(md5_final) 
	},
	{
	  HASH_SHA1, 
	  SHA1_DIGEST_LEN,
	  HASH_INIT(sha1_context_init),
	  HASH_UPDATE(sha1_update),
	  HASH_FINAL(sha1_final) 
	},
	{ 
	  HASH_SHA256,
	  SHA256_DIGEST_LEN,
	  HASH_INIT(sha256_context_init),
	  HASH_UPDATE(sha256_update),
	  HASH_FINAL(sha256_final) 
	}
};


int
entropy_pool_init(struct entropy_pool *pool,
		  int nsources,
		  const char *hash_name)
{

	int i;

	assert(pool != NULL && nsources > 0 && hash_name != NULL);

	pool->nsources = nsources;
	pool->k = DEFAULT_K;

	for (i = 0; i < MAXSOURCES; i++) {
		pool->threshold[i] = 0.0;
		pool->estimate[i] = 0.0;
	}

	pool->hdesc = hash_desc_get(hash_name);
	pool->hdesc->init(&pool->hash_ctx);
	
	if (pool->hdesc == NULL)
		return EPOOL_FAIL;
	
	return EPOOL_OK;
	
}

int
entropy_pool_add(struct entropy_pool *pool,
		 int source_id,
		 const void *buf,
		 size_t len,
		 double estimate)
{
	float nbits;
	assert( pool != NULL && source_id >= 0 && buf != NULL);

	printf("Debug pool_nsources = %d "
	       "source_id %d "
	       "buf %p "
	       "pool %p \n ", pool->nsources, source_id, buf, pool);

	if (source_id >= pool->nsources)
		return EPOOL_FAIL;

	nbits = len * CHAR_BIT * estimate;
	printf("nbits %f esitmate %f, len %d \n", nbits, estimate, (int ) len);
	pool->estimate[source_id] += nbits;

	pool->hdesc->update(&pool->hash_ctx, buf, len);
	pool->hdesc->finalize(&pool->hash_ctx, pool->buffer);

	return EPOOL_OK;
}

int
entropy_pool_is_thresholded(struct entropy_pool *pool)
{
	assert(pool != NULL);

	int i, c;
	c = 0;
	
	for (i = 0; i < pool->nsources; i++){
		if (pool->estimate[i] >= pool->threshold[i])
			c++;
		if (c == pool->k )
			return TRUE;
	}
	
	return FALSE;
}

int
entropy_pool_feed_to(struct entropy_pool *dst, struct entropy_pool *src)
{
	assert(dst != NULL || src != NULL);

	src->hdesc->finalize(&src->hash_ctx, (void *)(src->buffer));
	printf(" digest_len %d \n", src->hdesc->digest_len);
	dst->hdesc->update(&dst->hash_ctx, (const void *)src->buffer, src->hdesc->digest_len); 
	
	return EPOOL_OK;
}

int
entropy_pool_deinit(struct entropy_pool *pool)
{
	int i;

	pool->hdesc 	= NULL;
	pool->nsources	= 0;
	pool->k		= 0;
	
	for (i = 0; i < pool->nsources; i++) {
		pool->threshold[i] = 0.0;
		pool->estimate[i] = 0.0;
	}

	return EPOOL_OK;
}


int
entropy_pool_set_k(struct entropy_pool *pool, int k)
{
	assert(pool != NULL && k > 0 && k < pool->nsources);

	pool->k = k;
	return EPOOL_OK;
}


int
entropy_pool_get_k(struct entropy_pool *pool)
{
	assert(pool != NULL);
	return pool->k;
}
 
int
entropy_pool_set_threshold(struct entropy_pool *pool, int source_id, double threshold)
{
	assert(pool != NULL && source_id >= 0 && threshold > 0);

	pool->threshold[source_id] = threshold;
	return EPOOL_OK;
}

double
entropy_pool_get_threshold(struct entropy_pool *pool, int source_id)
{
	assert(pool != NULL && source_id >= 0);
	return pool->threshold[source_id];
}

int
entropy_pool_set_nsources(struct entropy_pool *pool, int nsources)
{
	assert(pool != NULL && nsources > 0);

	pool->nsources = nsources;
	return EPOOL_OK;
}

int
entropy_pool_get_nsources(struct entropy_pool *pool)
{
	assert(pool != NULL);
        return pool->nsources;
}

unsigned char *
entropy_pool_bytes(const struct entropy_pool *pool)
{
	assert(pool != NULL);
	return pool->buffer;
}


unsigned int
entropy_pool_length(const struct entropy_pool *pool)
{
	assert(pool != NULL);
	return pool->hdesc->digest_len;
}

void
entropy_pool_clean(struct entropy_pool *pool)
{
	int i;

	assert(pool != NULL);
	
	for (i = 0; i < pool->nsources; i++) {
		pool->threshold[i] = 0.0;
		pool->estimate[i] = 0.0;
	}
	
	for (i = 0; i < ARRAY_SIZE(pool->buffer); i++) {
		pool->buffer[i] = 0;
	}

	memset(&pool->hash_ctx, 0, sizeof(pool->hash_ctx));
	pool->hdesc = NULL;
}

struct hash_desc *
hash_desc_get(const char *hash_name)
{
	int i;

	assert(hash_name != 0);
	
	for ( i = 0; i < ARRAY_SIZE(desc_tbl); i++ ) {
		if (strcmp(hash_name, desc_tbl[i].name) == 0) {
			return &desc_tbl[i];
		}
	}

	return FALSE;
}

int 
prng_reseed(struct prng_context *prng, const struct entropy_pool *pool, int param)
{
	unsigned char *v0, digest[MAXDIGEST]; 
	unsigned char val[4];
	int i, len;
	struct gost_context *gost_ctx;

	v0 = entropy_pool_bytes(pool);
	len = entropy_pool_length(pool);

	prng->hdesc = hash_desc_get("sha1");

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

	for (i = 0; i < ARRAY_SIZE(digest); i++) {
		prng->key[i] = digest[i];
	}

	for (i = 0; i < ARRAY_SIZE(prng->counter); i++) {
		prng->counter[i] = 0;			
	}
	
	gost_ctx = gost_context_new();
	gost_set_key(gost_ctx, prng->key);
	gost_encrypt_32z(gost_ctx, (u_int32_t *) prng->counter);

	return TRUE;
}

