/*
 * SHA-256 -- US Secure Hash Algorithm 2 (SHA2).
 *
 * Implementation of SHA-256 specification FIPS PUB 180-2.
 *
 * Grisha Sitkarev, 2011 (c)
 * <sitkarev@unixkomi.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

#include "sha256.h"

#define BE32_FROM_PTR(ptr) \
	((((uint8_t *)(ptr))[0]) << 24 | (((uint8_t *)(ptr))[1]) << 16 | \
 	 (((uint8_t *)(ptr))[2]) << 8 | (((uint8_t *)(ptr))[3]))

/* Rotate 32-bit word left. */
#define ROL32(x, n) \
	((((uint32_t)(x)) << (n)) | (((uint32_t)(x)) >> (32-(n))))

/* Rotate 32-bit word right. */
#define ROR32(x, n) \
	((((uint32_t)(x)) >> (n)) | (((uint32_t)(x)) << (32-(n))))

#define K00 0x428a2f98
#define K01 0x71374491
#define K02 0xb5c0fbcf
#define K03 0xe9b5dba5
#define K04 0x3956c25b
#define K05 0x59f111f1
#define K06 0x923f82a4
#define K07 0xab1c5ed5
#define K08 0xd807aa98
#define K09 0x12835b01
#define K10 0x243185be
#define K11 0x550c7dc3
#define K12 0x72be5d74 
#define K13 0x80deb1fe
#define K14 0x9bdc06a7
#define K15 0xc19bf174
#define K16 0xe49b69c1
#define K17 0xefbe4786
#define K18 0x0fc19dc6
#define K19 0x240ca1cc
#define K20 0x2de92c6f
#define K21 0x4a7484aa
#define K22 0x5cb0a9dc
#define K23 0x76f988da
#define K24 0x983e5152
#define K25 0xa831c66d
#define K26 0xb00327c8
#define K27 0xbf597fc7
#define K28 0xc6e00bf3
#define K29 0xd5a79147
#define K30 0x06ca6351
#define K31 0x14292967
#define K32 0x27b70a85
#define K33 0x2e1b2138
#define K34 0x4d2c6dfc
#define K35 0x53380d13
#define K36 0x650a7354
#define K37 0x766a0abb
#define K38 0x81c2c92e
#define K39 0x92722c85
#define K40 0xa2bfe8a1
#define K41 0xa81a664b
#define K42 0xc24b8b70
#define K43 0xc76c51a3
#define K44 0xd192e819
#define K45 0xd6990624
#define K46 0xf40e3585
#define K47 0x106aa070
#define K48 0x19a4c116
#define K49 0x1e376c08
#define K50 0x2748774c
#define K51 0x34b0bcb5
#define K52 0x391c0cb3
#define K53 0x4ed8aa4a
#define K54 0x5b9cca4f
#define K55 0x682e6ff3
#define K56 0x748f82ee
#define K57 0x78a5636f
#define K58 0x84c87814
#define K59 0x8cc70208
#define K60 0x90befffa
#define K61 0xa4506ceb
#define K62 0xbef9a3f7
#define K63 0xc67178f2

#define CH(x, y, z)	(((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)	(ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define BSIG1(x)	(ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SSIG0(x)	(ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)	(ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

#define SHA256_BASIC(a, b, c, d, e, f, g, h, K, W, T1, T2) \
{ \
	T1 = h + BSIG1(e) + CH(e, f, g) + K + W; \
	T2 = BSIG0(a) + MAJ(a, b, c); \
	h = g; \
	g = f; \
	f = e; \
	e = d + T1; \
	d = c; \
	c = b; \
	b = a; \
	a = T1 + T2; \
}

void
sha256_hash(uint32_t s[8], const unsigned char buffer[64])
{
	uint32_t W[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t T1, T2;

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

	W[16] = SSIG1(W[14]) + W[ 9] + SSIG0(W[ 1]) + W[ 0];
	W[17] = SSIG1(W[15]) + W[10] + SSIG0(W[ 2]) + W[ 1];
	W[18] = SSIG1(W[16]) + W[11] + SSIG0(W[ 3]) + W[ 2];
	W[19] = SSIG1(W[17]) + W[12] + SSIG0(W[ 4]) + W[ 3];
	W[20] = SSIG1(W[18]) + W[13] + SSIG0(W[ 5]) + W[ 4];
	W[21] = SSIG1(W[19]) + W[14] + SSIG0(W[ 6]) + W[ 5];
	W[22] = SSIG1(W[20]) + W[15] + SSIG0(W[ 7]) + W[ 6];
	W[23] = SSIG1(W[21]) + W[16] + SSIG0(W[ 8]) + W[ 7];
	W[24] = SSIG1(W[22]) + W[17] + SSIG0(W[ 9]) + W[ 8];
	W[25] = SSIG1(W[23]) + W[18] + SSIG0(W[10]) + W[ 9];
	W[26] = SSIG1(W[24]) + W[19] + SSIG0(W[11]) + W[10];
	W[27] = SSIG1(W[25]) + W[20] + SSIG0(W[12]) + W[11];
	W[28] = SSIG1(W[26]) + W[21] + SSIG0(W[13]) + W[12];
	W[29] = SSIG1(W[27]) + W[22] + SSIG0(W[14]) + W[13];
	W[30] = SSIG1(W[28]) + W[23] + SSIG0(W[15]) + W[14];
	W[31] = SSIG1(W[29]) + W[24] + SSIG0(W[16]) + W[15];
	W[32] = SSIG1(W[30]) + W[25] + SSIG0(W[17]) + W[16];
	W[33] = SSIG1(W[31]) + W[26] + SSIG0(W[18]) + W[17];
	W[34] = SSIG1(W[32]) + W[27] + SSIG0(W[19]) + W[18];
	W[35] = SSIG1(W[33]) + W[28] + SSIG0(W[20]) + W[19];
	W[36] = SSIG1(W[34]) + W[29] + SSIG0(W[21]) + W[20];
	W[37] = SSIG1(W[35]) + W[30] + SSIG0(W[22]) + W[21];
	W[38] = SSIG1(W[36]) + W[31] + SSIG0(W[23]) + W[22];
	W[39] = SSIG1(W[37]) + W[32] + SSIG0(W[24]) + W[23];
	W[40] = SSIG1(W[38]) + W[33] + SSIG0(W[25]) + W[24];
	W[41] = SSIG1(W[39]) + W[34] + SSIG0(W[26]) + W[25];
	W[42] = SSIG1(W[40]) + W[35] + SSIG0(W[27]) + W[26];
	W[43] = SSIG1(W[41]) + W[36] + SSIG0(W[28]) + W[27];
	W[44] = SSIG1(W[42]) + W[37] + SSIG0(W[29]) + W[28];
	W[45] = SSIG1(W[43]) + W[38] + SSIG0(W[30]) + W[29];
	W[46] = SSIG1(W[44]) + W[39] + SSIG0(W[31]) + W[30];
	W[47] = SSIG1(W[45]) + W[40] + SSIG0(W[32]) + W[31];
	W[48] = SSIG1(W[46]) + W[41] + SSIG0(W[33]) + W[32];
	W[49] = SSIG1(W[47]) + W[42] + SSIG0(W[34]) + W[33];
	W[50] = SSIG1(W[48]) + W[43] + SSIG0(W[35]) + W[34];
	W[51] = SSIG1(W[49]) + W[44] + SSIG0(W[36]) + W[35];
	W[52] = SSIG1(W[50]) + W[45] + SSIG0(W[37]) + W[36];
	W[53] = SSIG1(W[51]) + W[46] + SSIG0(W[38]) + W[37];
	W[54] = SSIG1(W[52]) + W[47] + SSIG0(W[39]) + W[38];
	W[55] = SSIG1(W[53]) + W[48] + SSIG0(W[40]) + W[39];
	W[56] = SSIG1(W[54]) + W[49] + SSIG0(W[41]) + W[40];
	W[57] = SSIG1(W[55]) + W[50] + SSIG0(W[42]) + W[41];
	W[58] = SSIG1(W[56]) + W[51] + SSIG0(W[43]) + W[42];
	W[59] = SSIG1(W[57]) + W[52] + SSIG0(W[44]) + W[43];
	W[60] = SSIG1(W[58]) + W[53] + SSIG0(W[45]) + W[44];
	W[61] = SSIG1(W[59]) + W[54] + SSIG0(W[46]) + W[45];
	W[62] = SSIG1(W[60]) + W[55] + SSIG0(W[47]) + W[46];
	W[63] = SSIG1(W[61]) + W[56] + SSIG0(W[48]) + W[47];
	
	a = s[0];
	b = s[1];
	c = s[2];
	d = s[3];
	e = s[4];
	f = s[5];
	g = s[6];
	h = s[7];
	
	SHA256_BASIC(a, b, c, d, e, f, g, h, K00, W[ 0], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K01, W[ 1], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K02, W[ 2], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K03, W[ 3], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K04, W[ 4], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K05, W[ 5], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K06, W[ 6], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K07, W[ 7], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K08, W[ 8], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K09, W[ 9], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K10, W[10], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K11, W[11], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K12, W[12], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K13, W[13], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K14, W[14], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K15, W[15], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K16, W[16], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K17, W[17], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K18, W[18], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K19, W[19], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K20, W[20], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K21, W[21], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K22, W[22], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K23, W[23], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K24, W[24], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K25, W[25], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K26, W[26], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K27, W[27], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K28, W[28], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K29, W[29], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K30, W[30], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K31, W[31], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K32, W[32], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K33, W[33], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K34, W[34], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K35, W[35], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K36, W[36], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K37, W[37], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K38, W[38], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K39, W[39], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K40, W[40], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K41, W[41], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K42, W[42], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K43, W[43], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K44, W[44], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K45, W[45], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K46, W[46], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K47, W[47], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K48, W[48], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K49, W[49], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K50, W[50], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K51, W[51], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K52, W[52], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K53, W[53], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K54, W[54], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K55, W[55], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K56, W[56], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K57, W[57], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K58, W[58], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K59, W[59], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K60, W[60], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K61, W[61], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K62, W[62], T1, T2);
	SHA256_BASIC(a, b, c, d, e, f, g, h, K63, W[63], T1, T2);
	
	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
	s[4] += e;
	s[5] += f;
	s[6] += g;
	s[7] += h;
}

void
sha256_context_init(struct sha256_context *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;

	memset(ctx->buffer, 0, sizeof(ctx->buffer));
	memset(ctx->state, 0, sizeof(ctx->state));
	
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void
sha256_update(struct sha256_context *ctx, const void *msg, u_int32_t msglen)
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

		sha256_hash(ctx->state, ctx->buffer);

		/* Transform rest of the message. */
		while (msglen >= 64) {
			sha256_hash(ctx->state, msg);
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
sha256_final(struct sha256_context *ctx, unsigned char digest[32])
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
	sha256_update(ctx, pad, npad);
	sha256_update(ctx, nb, 8);

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_to_bytes(digest, ctx->state, 8);
#elif __BYTE_ORDER == __BIG_ENDIAN
	memcpy(digest, ctx->state, 32);
#else
#error unknown byte order!
#endif
}

