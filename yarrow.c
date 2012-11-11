#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "limits.h"
#include "yarrow.h"
#include "entropy_pool.h"
#include "hash_desc.h"

#define ARRSZ(a) (sizeof(a)/a[0])
#define DEFAULT_NSOURCES 3

#define HASH_INIT(x) ((void (*)(void *))(x))
#define HASH_UPDATE(x) ((void (*)(void *, const void *, size_t))(x))
#define HASH_FINAL(x) ((void * (*)(void *, unsigned char *))(x))

struct hash_desc desc_tbl[] = {
	{ HASH_MD5,
	  MD5_DIGEST_LEN, 
	  HASH_INIT(md5_context_init),
	  HASH_UPDATE(md5_update),
	  HASH_FINAL(md5_final) },
	{ HASH_SHA1, 20, NULL, NULL, NULL },
	{ HASH_SHA256, 32, NULL, NULL, NULL }
};


int
entropy_pool_init(struct entropy_pool *pool,
		  int nsources,
		  const char *hash_name)
{

	int i;

	assert(pool != NULL && nsources > 0 && hash_name != NULL);

	pool->nsources = nsources;
	pool->k = DEFAULT_NSOURCES;

	for (i = 0; i < MAXSOURCES; i++) {
		pool->threshold[i] = 0.0;
		pool->estimate[i] = 0.0;
	}

	for ( i = 0; i < 3; i++ ) {
		if (strcmp(hash_name, desc_tbl[i].name) == 0) { 
			pool->hdesc = &desc_tbl[i];
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
	float res;
	assert( pool != NULL && source_id >= 0 && buf != NULL && len > 0);

	res = len * CHAR_BIT * estimate;
	pool->estimate[source_id] += res;

	pool->hdesc->init(&pool->hash_ctx);
	pool->hdesc->update(&pool->hash_ctx, (void *)buf, len);


	return EPOOL_OK;
}

/*
int
entropy_pool_deinit(struct entropy_pool *pool)
{
	pool->hdesc 	= NULL;
	pool->nsources	= 0;

	return 0;
}

int
entropy_pool_set_k(struct entropy_pool *pool, int k)
{
	assert(pool != NULL && k > 0 && k < pool->nsources);
// k <0 && k < nsourea
	pool->k = k;

	return 0;
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
entropy_pool_is_thresholded(struct entropy_pool *pool)
{
	assert(pool != NULL);

	int i, c;
	c = 0;
	
	for (i = 0; i < pool->nsources; i++){
		if (pool->threshold[i] >= THRESHOLD)
			c++;
		if (c == pool->k )
			return TRUE;
	}
	
	return FALSE;
}

int
entropy_pool_feed_to(struct entropy_pool *dst, const struct entropy_pool *src)
{
	assert(dst != NULL || src != NULL);


	memcpy(dst, src, size);
	//???
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
