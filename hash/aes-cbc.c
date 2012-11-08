#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "macros.h"
#include "aes-cbc.h"

#define BLOCKSZ		16

#define CBC_ENCRYPT	1	
#define CBC_DECRYPT	0

#define CBC(out, iv) \
{ \
	uint32_t *p = (uint32_t *) (out); \
	uint32_t *p2 = (uint32_t *) (iv); \
	*p++ ^= *p2++; *p++ ^= *p2++; \
	*p++ ^= *p2++; *p++ ^= *p2++; \
}

void
aes_cbc_clean(struct aes_cbc *cbc)
{
	assert(cbc != NULL);
	memset(cbc->iv, 0, sizeof(cbc->iv));
	memset(cbc->buffer, 0, sizeof(cbc->buffer));
}

void
aes_cbc_init(struct aes_cbc *cbc,
	     void (*encode)(void *ctx, const void *in, void *out),
	     void *ctx, int encr, const unsigned char iv[16])
{
	return_if_fail(cbc != NULL);
	return_if_fail(encode != NULL && iv != NULL);

	memcpy(cbc->iv, iv, sizeof(cbc->iv));
	memset(cbc->buffer, 0, sizeof(cbc->buffer));
	cbc->len = 0;
	cbc->encode = encode;
	cbc->ctx = ctx;
	cbc->mode = encr ? CBC_ENCRYPT : CBC_DECRYPT;
}

void
aes_cbc_update(struct aes_cbc *cbc, void *out, unsigned *olen, const void *in, unsigned ilen)
{
	unsigned int n, space;

	return_if_fail(cbc != NULL && in != NULL);
	return_if_fail(out != NULL && olen != NULL);

	n = cbc->len;
	space = BLOCKSZ - n;
	*olen = 0;

	if (n > 0 && space > 0) {
		memcpy(cbc->buffer + n, in, space);
		cbc->len += n;
		ilen -= n;
		in += n;
	}

	if (cbc->len >= BLOCKSZ) {

		if (cbc->mode == CBC_ENCRYPT)
			CBC(cbc->buffer, cbc->iv);

		(*cbc->encode)(cbc->ctx, cbc->buffer, out);
			
		if (cbc->mode == CBC_DECRYPT)
			CBC(out, cbc->iv);
				
		/* Save output block for chaining with the next. */
		if (cbc->mode == CBC_ENCRYPT)
			memcpy(cbc->iv, out, BLOCKSZ);
		else
			memcpy(cbc->iv, cbc->buffer, BLOCKSZ);
				
		*olen += BLOCKSZ;
		out += BLOCKSZ;
		cbc->len = 0;
	}
	
	while (ilen >= BLOCKSZ) {

		/* Put input block to output buffer immediately. */
		memcpy(out, in, BLOCKSZ);
		/* Apply block chaining when in encryption mode. */
		if (cbc->mode == CBC_ENCRYPT)
			CBC(out, cbc->iv);
		/* Encode output block in-place. */
		(*cbc->encode)(cbc->ctx, out, out);

		/* Apply block chaining when in decryption mode. */
		if (cbc->mode == CBC_DECRYPT)
			CBC(out, cbc->iv);
		
		/* Save current block for chaining the next one. */
		if (cbc->mode == CBC_ENCRYPT)
			memcpy(cbc->iv, out, BLOCKSZ);
		else
			memcpy(cbc->iv, in, BLOCKSZ);
		
		out += BLOCKSZ;
		in += BLOCKSZ;
		*olen += BLOCKSZ;
		ilen -= BLOCKSZ;
	}

	if (ilen > 0) {
		n = cbc->len;
		memcpy(cbc->buffer + n, in, ilen);
		cbc->len += ilen;
	}
}

void
aes_cbc_final(struct aes_cbc *cbc, void *out, unsigned *olen)
{
	unsigned n, space;

	return_if_fail(cbc != NULL);
	return_if_fail(out != NULL && olen != NULL);

	n = cbc->len;
	space = BLOCKSZ - n;
	*olen = 0;

	if (n > 0) {

		/* Pad buffer with bytes of the same value as the number of padding bytes. */
		memset(cbc->buffer + n, space, space);

		if (cbc->mode == CBC_ENCRYPT)
			CBC(cbc->buffer, cbc->iv);

		/* Encode the final block. */
		(*cbc->encode)(cbc->ctx, cbc->buffer, out);
	
		if (cbc->mode == CBC_DECRYPT)
			CBC(out, cbc->iv);

		*olen = n;
	}
}

