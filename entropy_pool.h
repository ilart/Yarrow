#ifndef _ENTROPY_POOL_H
#define _ENTROPY_POOL_H

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "hash_desc.h"

#define MAXSOURCES 32

enum {
	EPOOL_OK = 0,
	EPOOL_FAIL = 1
};

struct entropy_pool {
	/* hash implementation to use with the pool */
	struct hash_desc *hdesc;

	/* number of entropy sources */
	int nsources;

	/* number of sources required to reach their watermarks */
	int k;

	/* entropy threshold values (in bits) for each source */
	float threshold[MAXSOURCES];

	/* entropy estimation (in bits) for each source */
	float estimate[MAXSOURCES];

	/* current hash */ 
	unsigned char buffer[MAXDIGEST];

	/* hash context */
	union _hash_ctx {
		struct md5_context md5; 
		struct sha1_context sha1;
		struct sha256_context sha256;
	} hash_ctx;
};

int entropy_pool_init(struct entropy_pool *pool, int nsources, const char *hash_name);

int entropy_pool_deinit(struct entropy_pool *pool);

int entropy_pool_set_k(struct entropy_pool *pool, int k);

int entropy_pool_get_k(struct entropy_pool *pool);

int entropy_pool_add(struct entropy_pool *pool, int source_id, const void *buf, size_t len, double estimate);

int entropy_pool_set_threshold(struct entropy_pool *pool, int source_id, double threshold);

double entropy_pool_get_threshold(struct entropy_pool *pool, int source_id);

int entropy_pool_is_thresholded(struct entropy_pool *pool);

int entropy_pool_feed_to(struct entropy_pool *dst, struct entropy_pool *src);

int entropy_pool_set_nsources(struct entropy_pool *pool, int nsources);

int entropy_pool_get_nsources(struct entropy_pool *pool);

unsigned char *entropy_pool_bytes(const struct entropy_pool *pool);

unsigned int entropy_pool_length(const struct entropy_pool *pool);

void entropy_pool_clean(struct entropy_pool *pool);

#endif /* _ENTROPY_POOL_H */


