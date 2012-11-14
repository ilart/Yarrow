#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <limits.h>
#include "yarrow.h"
#include "macros.h"

#define ARRSZ(a) (sizeof(a)/sizeof(a[0]))
#define DEFAULT_K 3
#define BUF_SZ 64

#define HASH_INIT(x) ((void (*)(void *))(x))
#define HASH_UPDATE(x) ((void (*)(void *, const void *, size_t))(x))
#define HASH_FINAL(x) ((void * (*)(void *, unsigned char *))(x))

struct hash_desc desc_tbl[] = {
	{ HASH_MD5,
	  MD5_DIGEST_LEN, 
	  HASH_INIT(md5_context_init),
	  HASH_UPDATE(md5_update),
	  HASH_FINAL(md5_final) },
	{ HASH_SHA1, 
	  SHA1_DIGEST_LEN,
	  HASH_INIT(sha1_context_init),
	  HASH_UPDATE(sha1_update),
	  HASH_FINAL(sha1_final) },
	{ HASH_SHA256,
	  SHA256_DIGEST_LEN,
	  HASH_INIT(sha256_context_init),
	  HASH_UPDATE(sha256_update),
	  HASH_FINAL(sha256_final) },
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

	for ( i = 0; i < ARRSZ(desc_tbl); i++ ) { /* does not  work with ARRSZ*/
		if (strcmp(hash_name, desc_tbl[i].name) == 0) { 
			pool->hdesc = &desc_tbl[i];
			pool->hdesc->init(&pool->hash_ctx);
			return EPOOL_OK;
		}
	}
	return EPOOL_FAIL;
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
			return EPOOL_OK;
	}
	
	return EPOOL_FAIL;
}

int
entropy_pool_feed_to(struct entropy_pool *dst, const struct entropy_pool *src)
{
	assert(dst != NULL || src != NULL);

	printf("fast_pool %p, slow_pool %p \n", dst, src );
//	dst->hdesc->update(&dst->hash_ctx, src->hdesc->finalize(), src->hdesc->digest_len); /*where are need current hash*/
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
 
/*


int
entropy_pool_set_threshold(struct entropy_pool *pool, int source_id, double threshold)
{

	pool->threshold[source_id] = threshold;

	return 0;
}

double
entropy_pool_get_threshold(struct entropy_pool *pool, int source_id)
{
	assert(pool != NULL);
	return pool->threshold[source_id];
}


int
entropy_pool_set_nsources(struct entropy_pool *pool, int nsources)
{
	assert(pool != NULL);
	pool->nsources = nsources;
	return 0;
}

int
entropy_pool_get_nsources(struct entropy_pool *pool)
{
	assert(pool != NULL);
        return pool->nsources;
}

unsigned char
*entropy_pool_bytes(struct entropy_pool *pool)
{

}

unsigned int
entropy_pool_length(struct entropy_pool *pool)
{

}

void
entropy_pool_clean(struct entropy_pool *pool)
{
	assert(pool != NULL);
	memset(pool->hash_ctx, 0, sizeof())
}*/
