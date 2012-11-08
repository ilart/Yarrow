#ifndef EMEOAEP_H_
#define EMEOAEP_H_

/*
 * PKCSv2 EME-OAEP transformation implementation.
 *
 * These routines are used by RSA-OAEP encryption/decryption.
 */

/* SHA-1 based EME-OAEP */
int emeoaep_sha1_encode(const void *m, unsigned mlen, const void *p, unsigned plen,
		int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
		void *em, int emlen);

int emeoaep_sha1_decode(const void *em, unsigned emlen, void *m, int mlen, unsigned char phash[20]);

/* SHA-256 based EME-OAEP */
int emeoaep_sha256_encode(const void *m, unsigned mlen, const void *p, unsigned plen,
		int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
		void *em, int emlen);

int emeoaep_sha256_decode(const void *em, unsigned emlen, void *m, int mlen, unsigned char phash[32]);

#endif

