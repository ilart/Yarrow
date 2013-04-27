#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include <unistd.h>
#include <stdint.h>
#include "macros.h"
#include "common.h"
#ifndef _HASH_H
#define _HASH_H

#define MAX_DIGEST	64

/*
    * Well-known hash implementations and their respective names.
     */
#define HASH_MD5	"md5"
#define HASH_SHA1	"sha1"
#define HASH_SHA256	"sha256"

/*
 * Hash function implementation description.
 *
 * Each hash function implementation must provide this structure.
 * Entropy pool selects one of the implemenations using its unique name.
*/
union _hash_ctx {
		struct md5_context md5; 
		struct sha1_context sha1;
		struct sha256_context sha256;
};


struct hash_desc {
	/* unique hash name as a null-terminated sting */
	const char *name;

	/* length of the digest (in bytes) */
	int digest_len;

	/* initialization function */
	void (*init)(void *ctx);

	/* update function feeds buffer `buf' of `len' bytes into hash */
	void (*update)(void *ctx, const void *buf, size_t len);

	/* finalize function outputs hash digest to `digest' */
	void *(*finalize)(void *ctx, unsigned char digest[MAX_DIGEST]);

};


struct hash_desc *hash_desc_get(const char *name);
#endif	/* _HASH_H_ */
