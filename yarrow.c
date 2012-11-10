#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <stdint.h>
#include "macros.h"
#include "yarrow.h"

struct hash_desc description[] = {
	{ HASH_MD5, 16, NULL, NULL, NULL, NULL },
	{ HASH_SHA1, 20, NULL, NULL, NULL, NULL },
	{ HASH_SHA256, 32, NULL, NULL, NULL, NULL }
}


int
entropy_pool_init(struct entropy_pool *pool,
			int nsources,
			const char *hash_name)
{

	assert(pool != NULL && nsources > 0 && hash_name != NULL);
		
	int i;

	pool->nsources = nsources;

	pool->k = 0;

	for (i = 0; i < MAXSOURCES; i++) {
		pool->hreshold[i] = 0.0;
		pool->estimate[i] = 0.0;
	}

	if (strcmp(HASH_MD5, hash_name) == 0) {
		pool->hash_desc = hash_ctx[0];
	}

	else if (strcmp(HASH_SHA1, hash_name) == 0) {
		pool->hash_desc = hash_ctx[1];
	}
	else if (strcmp(HASH_SHA256,hash_name) == 0) {
		pool->hash_desc = hash_ctx[2];
	}
		
	
	else
		DEBUG(LOG_DEFAULT, "Invalid name of hash %s, \
		      use its one of list: md5, sha1, sha256 \n");

	return 0;
}

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
entropy_pool_add(struct entropy_pool *pool,
			int source_id,
			const void *buf,
			size_t len,
			double estimate,)
{
	int i;

	if (pool == NULL || buf == NULL){
        	DEBUG(LOG_DEFAULT, "pool or buf is NULL\n");
		return 1;
	}

	pool->estimate[sources_id] = estimate;

	i = pool->hdesc->hash_update(&pool->hash_ctx, buf, len);
//	pool->threshold[sources_id] = 0.0;

	return 0;
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
entropy_pool_feed_to(struct entropy_pool *dst, const struct entropy_pool *src, int size )
{
	assert(dst != NULL || src != NULL);

	memcpy(dst, src, size);
	return 0;
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
	memset(&pool->hash_ctx, 0, sizeof())
}
