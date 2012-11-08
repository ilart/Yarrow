#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha256.h"
#include "sha1.h"

int
emeoaep_sha1_encode(const void *m, unsigned mlen, const void *p, unsigned plen,
		    int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
		    void *em, unsigned emlen)
{
	unsigned char buffer[SHA1_DIGEST_LEN];
	unsigned char ival[4];
	struct sha1_context ctx;
	unsigned int n, pad;
	void *ptr, *dbp, *seedp;
	int i, q, r;

	if (m == NULL || em == NULL || rnd == NULL)
		return -1;

	n = emlen - 2*SHA1_DIGEST_LEN - 1;

	if (mlen > n)
		return -2;
	/* seedp is where the seed->maskedSeed are */
	seedp = em;

	/* dbp is where the DB->maskedDB will reside */
	dbp = em + SHA1_DIGEST_LEN;

	/* Calculate pHash and append it to DB. */
	ptr = dbp;
	sha1_context_init(&ctx);
	if (p != NULL && plen > 0)
		sha1_update(&ctx, p, plen);
	sha1_final(&ctx, ptr);
	ptr += SHA1_DIGEST_LEN;

	/* Append PS to DB. */
	pad = emlen - mlen - 2*SHA1_DIGEST_LEN - 1;
	for (i = 0; i < pad; i++)
		*((uint8_t *)ptr++) = 0;
	/* Append 0x01 to DB. */
	*((uint8_t *)ptr++) = 0x01;

	/* Append M to DB. */
	memcpy(ptr, m, mlen);

	/* Generate random seed. */
	
	(*rnd)(seedp, SHA1_DIGEST_LEN, rndctx);

	n = emlen - SHA1_DIGEST_LEN;
	q = n / SHA1_DIGEST_LEN;
	r = n % SHA1_DIGEST_LEN;

	ptr = dbp;

	for (i = 0; i < q; i++) {
		uint32_t *dst, *src;

		/* I2OSP transformation for counter, C = I2OSP(i, 4), */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;

		/* Concatenate seed and ival hash, T = T || Hash(Z||C).*/
		sha1_context_init(&ctx);
		sha1_update(&ctx, seedp, SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));
		sha1_final(&ctx, buffer);

		/* XOR mask with DB. */
		src = (uint32_t *) buffer;
		dst = (uint32_t *) ptr;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;

		n -= SHA1_DIGEST_LEN;
		ptr += SHA1_DIGEST_LEN;
	}

	if (r > 0) {
		int k;
		uint8_t *dst, *src;

		/* Output leading octets of T. */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;
		sha1_context_init(&ctx);
		sha1_update(&ctx, seedp, SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));		
		sha1_final(&ctx, buffer);

		dst = ptr;
		src = buffer;

		for (k = 0; k < n; k++)
			*dst++ ^= *src++;
	}

	{
		uint32_t *src, *dst;

		memset(ival, 0, 4);
		sha1_context_init(&ctx);
		sha1_update(&ctx, dbp, emlen - SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));
		sha1_final(&ctx, buffer);
		
		/* XOR mask with seed -> maskedSeed. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)seedp;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;
	}

	return 0;
}

int
emeoaep_sha1_decode(void *em, unsigned emlen, void *m, unsigned mlen, unsigned char phash[32])
{
	struct sha1_context ctx;
	unsigned char buffer[SHA1_DIGEST_LEN];
	unsigned char ival[4];
	int i, n, r, q, pad;
	void *dbp, *seedp;
	void *ptr;

	if (em == NULL)
		return -1;

	if (emlen < 2*SHA1_DIGEST_LEN + mlen + 1)
		return -2;

	/* seed pointer */
	seedp = em;

	/* DB pointer */
	dbp = em + SHA1_DIGEST_LEN;

	{
		uint32_t *src, *dst;

		memset(ival, 0, 4);
		sha1_context_init(&ctx);
		sha1_update(&ctx, dbp, emlen - SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));
		sha1_final(&ctx, buffer);
	
		/* XOR mask with maskedSeed -> Seed. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)seedp;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;
	}

	n = emlen - SHA1_DIGEST_LEN;
	q = n / SHA1_DIGEST_LEN;
	r = n % SHA1_DIGEST_LEN;

	ptr = dbp;

	for (i = 0; i < q; i++) {
		uint32_t *dst, *src;

		/* I2OSP transformation for counter, C = I2OSP(i, 4), */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;

		/* Concatenate seed and ival hash, T = T || Hash(Z||C).*/
		sha1_context_init(&ctx);
		sha1_update(&ctx, seedp, SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));
		sha1_final(&ctx, buffer);

		/* XOR mask with MaskedDB -> DB. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)ptr;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;

		n -= SHA1_DIGEST_LEN;
		ptr += SHA1_DIGEST_LEN;
	}

	if (r > 0) {
		int k;
		uint8_t *dst, *src;

		/* Output leading octets of T. */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;
		sha1_context_init(&ctx);
		sha1_update(&ctx, seedp, SHA1_DIGEST_LEN);
		sha1_update(&ctx, ival, sizeof(ival));		
		sha1_final(&ctx, buffer);

		dst = ptr;
		src = buffer;

		for (k = 0; k < n; k++)
			*dst++ ^= *src++;
	}

	pad = emlen - mlen - 2*SHA1_DIGEST_LEN - 1;

	/* Output pHash value. */
	if (phash != NULL)
		memcpy(phash, dbp, SHA1_DIGEST_LEN);

	/* Skip pHash, PS and 0x1. */
	ptr = dbp + SHA1_DIGEST_LEN + pad + 1;

	/* Output decoded message. */
	if (m != NULL)
		memcpy(m, ptr, mlen);

	return 0;
}

int
emeoaep_sha256_encode(const void *m, unsigned mlen, const void *p, unsigned plen,
		      int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
		      void *em, unsigned emlen)
{
	unsigned char buffer[SHA256_DIGEST_LEN];
	unsigned char ival[4];
	struct sha256_context ctx;
	unsigned int n, pad;
	void *ptr, *dbp, *seedp;
	int i, q, r;

	if (m == NULL || em == NULL || rnd == NULL)
		return -1;

	n = emlen - 2*SHA256_DIGEST_LEN - 1;

	if (mlen > n)
		return -2;
	/* seedp is where the seed->maskedSeed are */
	seedp = em;

	/* dbp is where the DB->maskedDB will reside */
	dbp = em + SHA256_DIGEST_LEN;

	/* Calculate pHash and append it to DB. */
	ptr = dbp;
	sha256_context_init(&ctx);
	if (p != NULL && plen > 0)
		sha256_update(&ctx, p, plen);
	sha256_final(&ctx, ptr);
	ptr += SHA256_DIGEST_LEN;

	/* Append PS to DB. */
	pad = emlen - mlen - 2*SHA256_DIGEST_LEN - 1;
	for (i = 0; i < pad; i++)
		*((uint8_t *)ptr++) = 0;
	/* Append 0x01 to DB. */
	*((uint8_t *)ptr++) = 0x01;

	/* Append M to DB. */
	memcpy(ptr, m, mlen);

	/* Generate random seed. */
	(*rnd)(seedp, SHA256_DIGEST_LEN, rndctx);

	n = emlen - SHA256_DIGEST_LEN;
	q = n / SHA256_DIGEST_LEN;
	r = n % SHA256_DIGEST_LEN;

	ptr = dbp;

	for (i = 0; i < q; i++) {
		uint32_t *dst, *src;

		/* I2OSP transformation for counter, C = I2OSP(i, 4), */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;

		/* Concatenate seed and ival hash, T = T || Hash(Z||C).*/
		sha256_context_init(&ctx);
		sha256_update(&ctx, seedp, SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));
		sha256_final(&ctx, buffer);

		/* XOR mask with DB. */
		src = (uint32_t *) buffer;
		dst = (uint32_t *) ptr;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;

		n -= SHA256_DIGEST_LEN;
		ptr += SHA256_DIGEST_LEN;
	}

	if (r > 0) {
		int k;
		uint8_t *dst, *src;

		/* Output leading octets of T. */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;
		sha256_context_init(&ctx);
		sha256_update(&ctx, seedp, SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));		
		sha256_final(&ctx, buffer);

		dst = ptr;
		src = buffer;

		for (k = 0; k < n; k++)
			*dst++ ^= *src++;
	}

	{
		uint32_t *src, *dst;

		memset(ival, 0, 4);
		sha256_context_init(&ctx);
		sha256_update(&ctx, dbp, emlen - SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));
		sha256_final(&ctx, buffer);
		
		/* XOR mask with seed -> maskedSeed. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)seedp;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;
	}

	return 0;
}

int
emeoaep_sha256_decode(void *em, unsigned emlen, void *m, unsigned mlen, unsigned char phash[32])
{
	struct sha256_context ctx;
	unsigned char buffer[SHA256_DIGEST_LEN];
	unsigned char ival[4];
	int i, n, r, q, pad;
	void *dbp, *seedp;
	void *ptr;

	if (em == NULL)
		return -1;

	if (emlen < 2*SHA256_DIGEST_LEN + mlen + 1)
		return -2;

	/* seed pointer */
	seedp = em;

	/* DB pointer */
	dbp = em + SHA256_DIGEST_LEN;

	{
		uint32_t *src, *dst;

		memset(ival, 0, 4);
		sha256_context_init(&ctx);
		sha256_update(&ctx, dbp, emlen - SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));
		sha256_final(&ctx, buffer);
	
		/* XOR mask with maskedSeed -> Seed. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)seedp;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;
	}

	n = emlen - SHA256_DIGEST_LEN;
	q = n / SHA256_DIGEST_LEN;
	r = n % SHA256_DIGEST_LEN;

	ptr = dbp;

	for (i = 0; i < q; i++) {
		uint32_t *dst, *src;

		/* I2OSP transformation for counter, C = I2OSP(i, 4), */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;

		/* Concatenate seed and ival hash, T = T || Hash(Z||C).*/
		sha256_context_init(&ctx);
		sha256_update(&ctx, seedp, SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));
		sha256_final(&ctx, buffer);

		/* XOR mask with MaskedDB -> DB. */
		src = (uint32_t *)buffer;
		dst = (uint32_t *)ptr;

		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst++ ^= *src++;
		*dst ^= *src;

		n -= SHA256_DIGEST_LEN;
		ptr += SHA256_DIGEST_LEN;
	}

	if (r > 0) {
		int k;
		uint8_t *dst, *src;

		/* Output leading octets of T. */
		ival[3] = i & 0xff;
		ival[2] = (i & 0xff00) >> 8;
		ival[1] = (i & 0xff0000) >> 16;
		ival[0] = (i & 0xff000000) >> 24;
		sha256_context_init(&ctx);
		sha256_update(&ctx, seedp, SHA256_DIGEST_LEN);
		sha256_update(&ctx, ival, sizeof(ival));		
		sha256_final(&ctx, buffer);

		dst = ptr;
		src = buffer;

		for (k = 0; k < n; k++)
			*dst++ ^= *src++;
	}

	pad = emlen - mlen - 2*SHA256_DIGEST_LEN - 1;

	/* Output pHash value. */
	if (phash != NULL)
		memcpy(phash, dbp, SHA256_DIGEST_LEN);

	/* Skip pHash, PS and 0x1. */
	ptr = dbp + SHA256_DIGEST_LEN + pad + 1;

	/* Output decoded message. */
	if (m != NULL)
		memcpy(m, ptr, mlen);

	return 0;
}

