/*
 * SHA-1 -- US Secure Hash Algorithm 1 (SHA1).
 *
 * Implementation of SHA1 specification RFC 3147.
 *
 * Grisha Sitkarev, 2011 (c)
 * <sitkarev@unixkomi.ru>
 *
 */

/*
 * This implemenation is not the fastest one but I hope that this code will be
 * easy to understand and maintain during it's lifetime.
 *
 * G.S.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

#include "sha1.h"

#define BE32_FROM_PTR(ptr) \
	((((uint8_t *)(ptr))[0]) << 24 | (((uint8_t *)(ptr))[1]) << 16 | \
 	 (((uint8_t *)(ptr))[2]) << 8 | (((uint8_t *)(ptr))[3]))

/* Rotate 32-bit word left. */
#define ROL32(x, n) \
	((((uint32_t)(x)) << (n)) | (((uint32_t)(x)) >> (32-(n))))

/* Rotate 32-bit word right. */
#define ROR32(x, n) \
	((((uint32_t)(x)) >> (n)) | (((uint32_t)(x)) << (32-(n))))

#define T0(b, c, d)	(((b) & (c)) | (~(b) & (d)))
#define T1(b, c, d)	((b) ^ (c) ^ (d))
#define T2(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))

#define AA(a, b, c, d, e, W) \
{ \
	uint32_t tmp; \
	tmp = ROL32(a, 5) + T0(b, c, d) + e + 0x5a827999 + W; \
	e = d; \
	d = c; \
	c = ROL32(b, 30); \
	b = a; \
	a = tmp; \
}

#define BB(a, b, c, d, e, W) \
{ \
	uint32_t tmp; \
	tmp = ROL32(a, 5) + T1(b, c, d) + e + 0x6ed9eba1 + W; \
	e = d; \
	d = c; \
	c = ROL32(b, 30); \
	b = a; \
	a = tmp; \
}

#define CC(a, b, c, d, e, W) \
{ \
	uint32_t tmp; \
	tmp = ROL32(a, 5) + T2(b, c, d) + e + 0x8f1bbcdc + W; \
	e = d; \
	d = c; \
	c = ROL32(b, 30); \
	b = a; \
	a = tmp; \
}

#define DD(a, b, c, d, e, W) \
{ \
	uint32_t tmp; \
	tmp = ROL32(a, 5) + T1(b, c, d) + e + 0xca62c1d6 + W; \
	e = d; \
	d = c; \
	c = ROL32(b, 30); \
	b = a; \
	a = tmp; \
}

void
sha1_hash(uint32_t s[8], const unsigned char buffer[64])
{
	uint32_t W[80];
	uint32_t a, b, c, d, e;

	W[ 0] = BE32_FROM_PTR(buffer);
	W[ 1] = BE32_FROM_PTR(buffer + 4);
	W[ 2] = BE32_FROM_PTR(buffer + 8);
	W[ 3] = BE32_FROM_PTR(buffer + 12);
	W[ 4] = BE32_FROM_PTR(buffer + 16);
	W[ 5] = BE32_FROM_PTR(buffer + 20);
	W[ 6] = BE32_FROM_PTR(buffer + 24);
	W[ 7] = BE32_FROM_PTR(buffer + 28);
	W[ 8] = BE32_FROM_PTR(buffer + 32);
	W[ 9] = BE32_FROM_PTR(buffer + 36);
	W[10] = BE32_FROM_PTR(buffer + 40);
	W[11] = BE32_FROM_PTR(buffer + 44);
	W[12] = BE32_FROM_PTR(buffer + 48);
	W[13] = BE32_FROM_PTR(buffer + 52);
	W[14] = BE32_FROM_PTR(buffer + 56);
	W[15] = BE32_FROM_PTR(buffer + 60);

	W[16] = ROL32(W[13] ^ W[ 8] ^ W[ 2] ^ W[ 0], 1);
	W[17] = ROL32(W[14] ^ W[ 9] ^ W[ 3] ^ W[ 1], 1);
	W[18] = ROL32(W[15] ^ W[10] ^ W[ 4] ^ W[ 2], 1);
	W[19] = ROL32(W[16] ^ W[11] ^ W[ 5] ^ W[ 3], 1);
	W[20] = ROL32(W[17] ^ W[12] ^ W[ 6] ^ W[ 4], 1);
	W[21] = ROL32(W[18] ^ W[13] ^ W[ 7] ^ W[ 5], 1);
	W[22] = ROL32(W[19] ^ W[14] ^ W[ 8] ^ W[ 6], 1);
	W[23] = ROL32(W[20] ^ W[15] ^ W[ 9] ^ W[ 7], 1);
	W[24] = ROL32(W[21] ^ W[16] ^ W[10] ^ W[ 8], 1);
	W[25] = ROL32(W[22] ^ W[17] ^ W[11] ^ W[ 9], 1);
	W[26] = ROL32(W[23] ^ W[18] ^ W[12] ^ W[10], 1);
	W[27] = ROL32(W[24] ^ W[19] ^ W[13] ^ W[11], 1);
	W[28] = ROL32(W[25] ^ W[20] ^ W[14] ^ W[12], 1);
	W[29] = ROL32(W[26] ^ W[21] ^ W[15] ^ W[13], 1);
	W[30] = ROL32(W[27] ^ W[22] ^ W[16] ^ W[14], 1);
	W[31] = ROL32(W[28] ^ W[23] ^ W[17] ^ W[15], 1);
	W[32] = ROL32(W[29] ^ W[24] ^ W[18] ^ W[16], 1);
	W[33] = ROL32(W[30] ^ W[25] ^ W[19] ^ W[17], 1);
	W[34] = ROL32(W[31] ^ W[26] ^ W[20] ^ W[18], 1);
	W[35] = ROL32(W[32] ^ W[27] ^ W[21] ^ W[19], 1);
	W[36] = ROL32(W[33] ^ W[28] ^ W[22] ^ W[20], 1);
	W[37] = ROL32(W[34] ^ W[29] ^ W[23] ^ W[21], 1);
	W[38] = ROL32(W[35] ^ W[30] ^ W[24] ^ W[22], 1);
	W[39] = ROL32(W[36] ^ W[31] ^ W[25] ^ W[23], 1);
	W[40] = ROL32(W[37] ^ W[32] ^ W[26] ^ W[24], 1);
	W[41] = ROL32(W[38] ^ W[33] ^ W[27] ^ W[25], 1);
	W[42] = ROL32(W[39] ^ W[34] ^ W[28] ^ W[26], 1);
	W[43] = ROL32(W[40] ^ W[35] ^ W[29] ^ W[27], 1);
	W[44] = ROL32(W[41] ^ W[36] ^ W[30] ^ W[28], 1);
	W[45] = ROL32(W[42] ^ W[37] ^ W[31] ^ W[29], 1);
	W[46] = ROL32(W[43] ^ W[38] ^ W[32] ^ W[30], 1);
	W[47] = ROL32(W[44] ^ W[39] ^ W[33] ^ W[31], 1);
	W[48] = ROL32(W[45] ^ W[40] ^ W[34] ^ W[32], 1);
	W[49] = ROL32(W[46] ^ W[41] ^ W[35] ^ W[33], 1);
	W[50] = ROL32(W[47] ^ W[42] ^ W[36] ^ W[34], 1);
	W[51] = ROL32(W[48] ^ W[43] ^ W[37] ^ W[35], 1);
	W[52] = ROL32(W[49] ^ W[44] ^ W[38] ^ W[36], 1);
	W[53] = ROL32(W[50] ^ W[45] ^ W[39] ^ W[37], 1);
	W[54] = ROL32(W[51] ^ W[46] ^ W[40] ^ W[38], 1);
	W[55] = ROL32(W[52] ^ W[47] ^ W[41] ^ W[39], 1);
	W[56] = ROL32(W[53] ^ W[48] ^ W[42] ^ W[40], 1);
	W[57] = ROL32(W[54] ^ W[49] ^ W[43] ^ W[41], 1);
	W[58] = ROL32(W[55] ^ W[50] ^ W[44] ^ W[42], 1);
	W[59] = ROL32(W[56] ^ W[51] ^ W[45] ^ W[43], 1);
	W[60] = ROL32(W[57] ^ W[52] ^ W[46] ^ W[44], 1);
	W[61] = ROL32(W[58] ^ W[53] ^ W[47] ^ W[45], 1);
	W[62] = ROL32(W[59] ^ W[54] ^ W[48] ^ W[46], 1);
	W[63] = ROL32(W[60] ^ W[55] ^ W[49] ^ W[47], 1);
	W[64] = ROL32(W[61] ^ W[56] ^ W[50] ^ W[48], 1);
	W[65] = ROL32(W[62] ^ W[57] ^ W[51] ^ W[49], 1);
	W[66] = ROL32(W[63] ^ W[58] ^ W[52] ^ W[50], 1);
	W[67] = ROL32(W[64] ^ W[59] ^ W[53] ^ W[51], 1);
	W[68] = ROL32(W[65] ^ W[60] ^ W[54] ^ W[52], 1);
	W[69] = ROL32(W[66] ^ W[61] ^ W[55] ^ W[53], 1);
	W[70] = ROL32(W[67] ^ W[62] ^ W[56] ^ W[54], 1);
	W[71] = ROL32(W[68] ^ W[63] ^ W[57] ^ W[55], 1);
	W[72] = ROL32(W[69] ^ W[64] ^ W[58] ^ W[56], 1);
	W[73] = ROL32(W[70] ^ W[65] ^ W[59] ^ W[57], 1);
	W[74] = ROL32(W[71] ^ W[66] ^ W[60] ^ W[58], 1);
	W[75] = ROL32(W[72] ^ W[67] ^ W[61] ^ W[59], 1);
	W[76] = ROL32(W[73] ^ W[68] ^ W[62] ^ W[60], 1);
	W[77] = ROL32(W[74] ^ W[69] ^ W[63] ^ W[61], 1);
	W[78] = ROL32(W[75] ^ W[70] ^ W[64] ^ W[62], 1);
	W[79] = ROL32(W[76] ^ W[71] ^ W[65] ^ W[63], 1);

	a = s[0];
	b = s[1];
	c = s[2];
	d = s[3];
	e = s[4];

	AA(a, b, c, d, e, W[ 0]);
	AA(a, b, c, d, e, W[ 1]);
	AA(a, b, c, d, e, W[ 2]);
	AA(a, b, c, d, e, W[ 3]);
	AA(a, b, c, d, e, W[ 4]);
	AA(a, b, c, d, e, W[ 5]);
	AA(a, b, c, d, e, W[ 6]);
	AA(a, b, c, d, e, W[ 7]);
	AA(a, b, c, d, e, W[ 8]);
	AA(a, b, c, d, e, W[ 9]);
	AA(a, b, c, d, e, W[10]);
	AA(a, b, c, d, e, W[11]);
	AA(a, b, c, d, e, W[12]);
	AA(a, b, c, d, e, W[13]);
	AA(a, b, c, d, e, W[14]);
	AA(a, b, c, d, e, W[15]);
	AA(a, b, c, d, e, W[16]);
	AA(a, b, c, d, e, W[17]);
	AA(a, b, c, d, e, W[18]);
	AA(a, b, c, d, e, W[19]);

	BB(a, b, c, d, e, W[20]);
	BB(a, b, c, d, e, W[21]);
	BB(a, b, c, d, e, W[22]);
	BB(a, b, c, d, e, W[23]);
	BB(a, b, c, d, e, W[24]);
	BB(a, b, c, d, e, W[25]);
	BB(a, b, c, d, e, W[26]);
	BB(a, b, c, d, e, W[27]);
	BB(a, b, c, d, e, W[28]);
	BB(a, b, c, d, e, W[29]);
	BB(a, b, c, d, e, W[30]);
	BB(a, b, c, d, e, W[31]);
	BB(a, b, c, d, e, W[32]);
	BB(a, b, c, d, e, W[33]);
	BB(a, b, c, d, e, W[34]);
	BB(a, b, c, d, e, W[35]);
	BB(a, b, c, d, e, W[36]);
	BB(a, b, c, d, e, W[37]);
	BB(a, b, c, d, e, W[38]);
	BB(a, b, c, d, e, W[39]);

	CC(a, b, c, d, e, W[40]);
	CC(a, b, c, d, e, W[41]);
	CC(a, b, c, d, e, W[42]);
	CC(a, b, c, d, e, W[43]);
	CC(a, b, c, d, e, W[44]);
	CC(a, b, c, d, e, W[45]);
	CC(a, b, c, d, e, W[46]);
	CC(a, b, c, d, e, W[47]);
	CC(a, b, c, d, e, W[48]);
	CC(a, b, c, d, e, W[49]);
	CC(a, b, c, d, e, W[50]);
	CC(a, b, c, d, e, W[51]);
	CC(a, b, c, d, e, W[52]);
	CC(a, b, c, d, e, W[53]);
	CC(a, b, c, d, e, W[54]);
	CC(a, b, c, d, e, W[55]);
	CC(a, b, c, d, e, W[56]);
	CC(a, b, c, d, e, W[57]);
	CC(a, b, c, d, e, W[58]);
	CC(a, b, c, d, e, W[59]);

	DD(a, b, c, d, e, W[60]);
	DD(a, b, c, d, e, W[61]);
	DD(a, b, c, d, e, W[62]);
	DD(a, b, c, d, e, W[63]);
	DD(a, b, c, d, e, W[64]);
	DD(a, b, c, d, e, W[65]);
	DD(a, b, c, d, e, W[66]);
	DD(a, b, c, d, e, W[67]);
	DD(a, b, c, d, e, W[68]);
	DD(a, b, c, d, e, W[69]);
	DD(a, b, c, d, e, W[70]);
	DD(a, b, c, d, e, W[71]);
	DD(a, b, c, d, e, W[72]);
	DD(a, b, c, d, e, W[73]);
	DD(a, b, c, d, e, W[74]);
	DD(a, b, c, d, e, W[75]);
	DD(a, b, c, d, e, W[76]);
	DD(a, b, c, d, e, W[77]);
	DD(a, b, c, d, e, W[78]);
	DD(a, b, c, d, e, W[79]);

	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
	s[4] += e;
}

void
sha1_context_init(struct sha1_context *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;

	memset(ctx->buffer, 0, sizeof(ctx->buffer));
	memset(ctx->state, 0, sizeof(ctx->state));
	
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

void
sha1_update(struct sha1_context *ctx, const void *msg, u_int32_t msglen)
{
	unsigned int n, len;

	/* Get length of buffer used. */
	n = ctx->count[0] & 0x3f;

	/* How many space in buffer left? */
	len = 64 - n;

	/* Update bits length. */
	ctx->count[0] += msglen;
	/* Detect and fix overflow. */
	if (ctx->count[0] < msglen)
		++ctx->count[1];

	if (msglen >= len) {

		/* Fill buffer to 64 bytes. */
		memcpy(ctx->buffer + n, msg, len);
		msglen -= len;
		msg += len;

		sha1_hash(ctx->state, ctx->buffer);

		/* Transform rest of the message. */
		while (msglen >= 64) {
			sha1_hash(ctx->state, msg);
			msg += 64;
			msglen -= 64;
		}

		n = 0;
	}

	/* Save message bytes to buffer if any left unprocessed. */
	if (msglen > 0)
		memcpy(ctx->buffer+n, msg, msglen);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
/* converts n 32-bit words to bytes (MSB first) */
static void
uint32_to_bytes(unsigned char *out, const u_int32_t *in, unsigned int n)
{
	unsigned int x, y;

	for (x = y = 0; y < n; y++) {
		out[x++] = (in[y] >> 24) & 0xff;
		out[x++] = (in[y] >> 16) & 0xff;
		out[x++] = (in[y] >> 8) & 0xff;
		out[x++] = in[y] & 0xff;
	}
}
#endif

void
sha1_final(struct sha1_context *ctx, unsigned char digest[20])
{
	static const unsigned char pad[64] = { 0x80, 0x0 };
	unsigned int n, npad;
	uint32_t nbits[2];
	uint8_t nb[8];

	n = ctx->count[0] & 0x3f;
	npad = ((n < 56) ? 56: 120) - n; 

	nbits[0] = ctx->count[1] << 3;
	nbits[0] += ctx->count[0] >> 29;
	nbits[1] = ctx->count[0] << 3;

	memset(nb, 0, sizeof(nb));
	/* Calculate length before padding. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_to_bytes(nb, nbits, 2);
#elif __BYTE_ORDER == __BIG_ENDIAN
	memcpy(nb, nbits, 8);
#else
#error unknown byte order!
#endif

	/* Pad message and append 64-bit length. */
	sha1_update(ctx, pad, npad);
	sha1_update(ctx, nb, 8);

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_to_bytes(digest, ctx->state, 5);
#elif __BYTE_ORDER == __BIG_ENDIAN
	memcpy(digest, ctx->state, 20);
#else
#error unknown byte order!
#endif
}

