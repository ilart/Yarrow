/*
 *  MD5 implementation (RFC 1321).
 *
 *  This is an implementation of MD5 alrorithm defined by RFC 1321.
 *
 *  All functions and macroses were written from scratch and are not
 *  derived from RFC's reference implementation.
 *
 *  Grisha Sitkarev, <sitkarev@unixkomi.ru>, 2011 (c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
 
#include "md5.h"

static const unsigned char md5pad[64] = { 0x80 }; /* Other 63 bytes are zeroes. */

#define F(x, y, z)	(((x) & (y)) | ((~x) & (z)))
#define G(x, y, z)	(((x) & (z)) | ((y) & (~z)))
#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | (~z)))

#define ROL(x, n)	(((x) << (n)) | ((x) >> (32-(n))))

/* 
 * FF, GG, HH, II macroses implement MD5 round operations.
 * a, b, c, d: state 32-bit words
 * x: part of input block
 * n: amount of bits to rotate left
 * C: magic constant
 */

#define FF(a, b, c, d, x, n, C) \
do { \
	(a) += F((b), (c), (d)) + (x) + (C); \
	(a) = ROL((a), (n)); \
	(a) += (b); \
} while (0)

#define GG(a, b, c, d, x, n, C) \
do { \
	(a) += G((b), (c), (d)) + (x) + (C); \
	(a) = ROL((a), (n)); \
	(a) += (b); \
} while (0)

#define HH(a, b, c, d, x, n, C) \
do { \
	(a) += H((b), (c), (d)) + (x) + (C); \
	(a) = ROL((a), (n)); \
	(a) += (b); \
} while (0)

#define II(a, b, c, d, x, n, C) \
do { \
	(a) += I((b), (c), (d)) + (x) + (C); \
	(a) = ROL((a), (n)); \
	(a) += (b); \
} while (0)

/* Per-round left rotate amount. */
#define T00	7
#define T01	12
#define T02	17
#define T03	22
#define T10	5
#define T11	9
#define T12	14
#define T13	20
#define T20	4
#define T21	11
#define T22	16
#define T23	23
#define T30	6
#define T31	10
#define T32	15
#define T33	21

#if defined __x86_32__ || defined __x86_64__
#define FETCH_U32(x) (*(const u_int32_t *)(x))
#else
#define FETCH_U32(x) \
	(((u_int32_t) *((const u_int8_t*)(x))) | \
	(((u_int32_t) *((const u_int8_t*)(x) + 1)) << 8) | \
	(((u_int32_t) *((const u_int8_t*)(x) + 2)) << 16) | \
	(((u_int32_t) *((const u_int8_t*)(x) + 3)) << 24))
#endif

/* converts n 32-bit words to bytes */
static void
uint32_to_bytes(unsigned char *out, const u_int32_t *in, unsigned int n)
{
	unsigned int x, y;

	for (x = y = 0; y < n; y++) {
#if defined __x86_32__ || defined __x86_64__
		*((u_int32_t *)(out + x)) = in[y];
		x += 4;
#else
		out[x++] = in[y] & 0xff;
		out[x++] = (in[y] >> 8) & 0xff;
		out[x++] = (in[y] >> 16) & 0xff;
		out[x++] = (in[y] >> 24) & 0xff;
#endif
	}
}

/* performs MD5 transformation */
void
md5_transform(u_int32_t state[4], const unsigned char block[64])
{
	u_int32_t x[16];
	u_int32_t a, b, c, d;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	x[0]  = FETCH_U32(block +  0);
	x[1]  = FETCH_U32(block +  4);
	x[2]  = FETCH_U32(block +  8);
	x[3]  = FETCH_U32(block + 12);
	x[4]  = FETCH_U32(block + 16);
	x[5]  = FETCH_U32(block + 20);
	x[6]  = FETCH_U32(block + 24);
	x[7]  = FETCH_U32(block + 28);
	x[8]  = FETCH_U32(block + 32);
	x[9]  = FETCH_U32(block + 36);
	x[10] = FETCH_U32(block + 40);
	x[11] = FETCH_U32(block + 44);
	x[12] = FETCH_U32(block + 48);
	x[13] = FETCH_U32(block + 52);
	x[14] = FETCH_U32(block + 56);
	x[15] = FETCH_U32(block + 60);

	FF(a, b, c, d, x[0],  T00, 0xd76aa478UL);
	FF(d, a, b, c, x[1],  T01, 0xe8c7b756UL);
	FF(c, d, a, b, x[2],  T02, 0x242070dbUL);
	FF(b, c, d, a, x[3],  T03, 0xc1bdceeeUL);
	FF(a, b, c, d, x[4],  T00, 0xf57c0fafUL);
	FF(d, a, b, c, x[5],  T01, 0x4787c62aUL);
	FF(c, d, a, b, x[6],  T02, 0xa8304613UL);
	FF(b, c, d, a, x[7],  T03, 0xfd469501UL);
	FF(a, b, c, d, x[8],  T00, 0x698098d8UL);
	FF(d, a, b, c, x[9],  T01, 0x8b44f7afUL);
	FF(c, d, a, b, x[10], T02, 0xffff5bb1UL);
	FF(b, c, d, a, x[11], T03, 0x895cd7beUL);
	FF(a, b, c, d, x[12], T00, 0x6b901122UL);
	FF(d, a, b, c, x[13], T01, 0xfd987193UL);
	FF(c, d, a, b, x[14], T02, 0xa679438eUL);
	FF(b, c, d, a, x[15], T03, 0x49b40821UL);

 	GG(a, b, c, d, x[1],  T10, 0xf61e2562UL);
	GG(d, a, b, c, x[6],  T11, 0xc040b340UL);
	GG(c, d, a, b, x[11], T12, 0x265e5a51UL);
	GG(b, c, d, a, x[0],  T13, 0xe9b6c7aaUL);
	GG(a, b, c, d, x[5],  T10, 0xd62f105dUL);
	GG(d, a, b, c, x[10], T11, 0x02441453UL);
	GG(c, d, a, b, x[15], T12, 0xd8a1e681UL);
	GG(b, c, d, a, x[4],  T13, 0xe7d3fbc8UL);
	GG(a, b, c, d, x[9],  T10, 0x21e1cde6UL);
	GG(d, a, b, c, x[14], T11, 0xc33707d6UL);
	GG(c, d, a, b, x[3],  T12, 0xf4d50d87UL);
	GG(b, c, d, a, x[8],  T13, 0x455a14edUL);
	GG(a, b, c, d, x[13], T10, 0xa9e3e905UL);
	GG(d, a, b, c, x[2],  T11, 0xfcefa3f8UL);
	GG(c, d, a, b, x[7],  T12, 0x676f02d9UL);
	GG(b, c, d, a, x[12], T13, 0x8d2a4c8aUL);
  
	HH(a, b, c, d, x[5],  T20, 0xfffa3942UL);
	HH(d, a, b, c, x[8],  T21, 0x8771f681UL);
	HH(c, d, a, b, x[11], T22, 0x6d9d6122UL);
	HH(b, c, d, a, x[14], T23, 0xfde5380cUL);
	HH(a, b, c, d, x[1],  T20, 0xa4beea44UL);
	HH(d, a, b, c, x[4],  T21, 0x4bdecfa9UL);
	HH(c, d, a, b, x[7],  T22, 0xf6bb4b60UL);
	HH(b, c, d, a, x[10], T23, 0xbebfbc70UL);
	HH(a, b, c, d, x[13], T20, 0x289b7ec6UL);
	HH(d, a, b, c, x[0],  T21, 0xeaa127faUL);
	HH(c, d, a, b, x[3],  T22, 0xd4ef3085UL);
	HH(b, c, d, a, x[6],  T23, 0x04881d05UL);
	HH(a, b, c, d, x[9],  T20, 0xd9d4d039UL);
	HH(d, a, b, c, x[12], T21, 0xe6db99e5UL);
	HH(c, d, a, b, x[15], T22, 0x1fa27cf8UL);
	HH(b, c, d, a, x[2],  T23, 0xc4ac5665UL);

	II(a, b, c, d, x[0],  T30, 0xf4292244UL);
	II(d, a, b, c, x[7],  T31, 0x432aff97UL);
	II(c, d, a, b, x[14], T32, 0xab9423a7UL);
	II(b, c, d, a, x[5],  T33, 0xfc93a039UL);
	II(a, b, c, d, x[12], T30, 0x655b59c3UL);
	II(d, a, b, c, x[3],  T31, 0x8f0ccc92UL);
	II(c, d, a, b, x[10], T32, 0xffeff47dUL);
	II(b, c, d, a, x[1],  T33, 0x85845dd1UL);
	II(a, b, c, d, x[8],  T30, 0x6fa87e4fUL);
	II(d, a, b, c, x[15], T31, 0xfe2ce6e0UL);
	II(c, d, a, b, x[6],  T32, 0xa3014314UL);
	II(b, c, d, a, x[13], T33, 0x4e0811a1UL);
	II(a, b, c, d, x[4],  T30, 0xf7537e82UL);
	II(d, a, b, c, x[11], T31, 0xbd3af235UL);
	II(c, d, a, b, x[2],  T32, 0x2ad7d2bbUL);
	II(b, c, d, a, x[9],  T33, 0xeb86d391UL);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	x[0] = x[1] = x[2] = x[3] = x[4] = x[5] = x[6] = x[7] =
	x[8] = x[9] = x[10] = x[11] = x[12] = x[13] = x[15] = 0;
}

void
md5_context_init(struct md5_context *ctx)
{
	ctx->nbits[0] = ctx->nbits[1] = 0;

	ctx->state[0] = 0x67452301UL;
	ctx->state[1] = 0xefcdab89UL;
	ctx->state[2] = 0x98badcfeUL;
	ctx->state[3] = 0x10325476UL;
}

void
md5_update(struct md5_context *ctx, const void *msg, u_int32_t msglen)
{
	unsigned int n, len;

//	printf("This string printed from md5_update,"
//	       "msg = %s,\n", (char *)msg);

	/* Get length of buffer used. */
	n = (ctx->nbits[0] >> 3) & 0x3f;

	/* How many space in buffer left? */
	len = 64 - n;

	/* Update bits length. */
	ctx->nbits[0] += msglen << 3;
	/* Detect and fix overflow. */
	if (ctx->nbits[0] < (msglen << 3))
		++ctx->nbits[1];
	ctx->nbits[1] += msglen >> 29;

	if (msglen >= len) {

		/* Fill buffer to 64 bytes. */
		memcpy(ctx->buffer + n, msg, len);
		msglen -= len;
		msg += len;

		md5_transform(ctx->state, ctx->buffer);

		/* Transform rest of the message with MD5. */
		while (msglen >= 64) {
			md5_transform(ctx->state, msg);
			msg += 64;
			msglen -= 64;
		}

		n = 0;
	}

	/* Save message bytes to buffer if any left unprocessed. */
	memcpy(ctx->buffer+n, msg, msglen);
//	for ( i = 0; i < 64; i++)
//		printf("%u ", ctx->buffer[i]);
}

void *
md5_final(struct md5_context *ctx, unsigned char digest[16])
{
	unsigned int n, npad;
	u_int8_t nbits[8];

	n = (ctx->nbits[0] >> 3) & 0x3f;
	npad = ((n < 56) ? 56: 120) - n;

	/* Calculate length before padding. */
	uint32_to_bytes(nbits, ctx->nbits, 2);

	/* Pad message and append length. */
	md5_update(ctx, md5pad, npad);
	md5_update(ctx, nbits, 8);
	
	uint32_to_bytes(digest, ctx->state, 4);
	return digest;
}

