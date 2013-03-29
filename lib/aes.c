/*
 * AES -- Advanced Encryption Standard (FIPS PUB 197).
 *
 * Implements encryption/decryption routines for 128, 192 and 256 keys.
 *
 * Grisha Sitkarev, <sitkarev@unixkomi.ru> 2011 (c)
 */

#include <limits.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "macros.h"
#include "galois.h"
#include "sbox.h"
#include "aes.h"

#define AES_NB		4	/* state words */
#define AES_NR_MAX	14	/* maximum rounds */

/* Macro helper reverses bytes in the word when LE order required. */
#if __BYTE_ORDER == __BIG_ENDIAN
#define LE32(x)		(((x) << 24) | (((x) << 8) & 0xff0000) | \
		         (((x) >> 8) & 0xff00) | ((x) >> 24))
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define LE32(x)		(x)
#else
#error unsupported byte order
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LE32_FROM_BYTES(b0, b1, b2, b3)	\
	((b0 & 0xff) | ((b1 << 8) & 0xff00) | \
	 ((b2 << 16) & 0xff0000) | ((b3 << 24) & 0xff000000))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define LE32_FROM_BYTES(b0, b1, b2, b3) \
	((b3 & 0xff) | ((b2 << 8) & 0xff00) | \
	 ((b1 << 16) & 0xff0000) | ((b0 << 24) & 0xff000000))
#else
#error unsupported byte order
#endif

struct aes_context {
	/* secret cipher key */
	u_int32_t	key[8];
	/* key type */
	aes_key_len_t	klen;
	/* state array */
	u_int32_t	state[AES_NB];
	/* number of rounds */
	int		nr;
	/* number of 32-bit words comprising the state */
	int		nb;
	/* number of 32-bit key words */
	int		nk;
	/* expanded key */
	u_int32_t	w[AES_NB*(AES_NR_MAX+1)];
};


/* Sibstitutes each byte of the 32-bit word using S-Box. */
static u_int32_t
sub_word(u_int32_t x)
{
	u_int32_t y;

	y = rijndael_sbox[x & 0xff] |
	    rijndael_sbox[(x >> 8) & 0xff] << 8 |
	    rijndael_sbox[(x >> 16) & 0xff] << 16 |
	    rijndael_sbox[(x >> 24) & 0xff] << 24;

	return y;
}

/* Shifts 32-bit word { a0, a1, a2, a3 } -> { a1, a2, a3, a0 }. */
static u_int32_t
rot_word(u_int32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	x = (x >> 8) | (x << 24);
#elif __BYTE_ORDER == __BIG_ENDIAN
	x = (x << 8) | (x >> 24);
#else
#error unsupported byte order
#endif
	return x;
}

static void
add_round_key(struct aes_context *ctx, int round)
{
	u_int8_t *wp;
	u_int32_t rkey;
	int i, nb;

	assert(ctx != NULL);
	assert(round >= 0 && round < ctx->nr+1);

	nb = ctx->nb;
	wp = (u_int8_t *)(ctx->w + round*AES_NB);

	for (i = 0; i < ctx->nb; i++) {
		rkey = LE32_FROM_BYTES(wp[nb*0+i], wp[nb*1+i],
				       wp[nb*2+i], wp[nb*3+i]);
		ctx->state[i] ^= rkey;
	}
}

/* Expands the key into key schedule. */
static void
key_expansion(struct aes_context *ctx)
{
	/* Powers of 2 in GF(2^8), note that indexing starts from 1. */
	u_int32_t rcon[] = { 
		0x00, 0x01, 0x02, 0x04,
		0x08, 0x10, 0x20, 0x40,
		0x80, 0x1b, 0x36
	};

	u_int32_t temp;
	int i, c, nk, nr;

	nk = ctx->nk;
	nr = ctx->nr;
	c = ctx->nb * (ctx->nr + 1);

	for (i = nk; i < c; i++) {
		temp = ctx->w[i-1];
		if ((i % nk) == 0)
			temp = sub_word(rot_word(temp)) ^ LE32(rcon[i/nk]);
		else if (nk > 6 && (i % nk) == 4)
			temp = sub_word(temp);
		ctx->w[i] = ctx->w[i-nk] ^ temp;
	}
}

/* Substitutes S-Box bytes in state array. */
static void
sub_bytes(struct aes_context *ctx)
{
	u_int32_t x;
	int i;

	/* Take each byte from state and replase it using S-Box table. */

	for (i = 0; i < ctx->nb; i++) {
		x = ctx->state[i];
		x = rijndael_sbox[x & 0xff] |
		    rijndael_sbox[(x >> 8) & 0xff] << 8 |
		    rijndael_sbox[(x >> 16) & 0xff] << 16 |
		    rijndael_sbox[(x >> 24) & 0xff] << 24;
		ctx->state[i] = x;
	}
}

/* Substitutes inverse S-Box bytes in state array. */
static void
inv_sub_bytes(struct aes_context *ctx)
{
	u_int32_t x;
	int i;

	/* Take each byte from state and replase it using inverse S-Box table. */

	for (i = 0; i < ctx->nb; i++) {
		x = ctx->state[i];
		x = rijndael_isbox[x & 0xff] |
		    rijndael_isbox[(x >> 8) & 0xff] << 8 |
		    rijndael_isbox[(x >> 16) & 0xff] << 16 |
		    rijndael_isbox[(x >> 24) & 0xff] << 24;
		ctx->state[i] = x;
	}
}

/* Does cyclical shift in state columns. */
static void
shift_rows(struct aes_context *ctx)
{
	u_int32_t *s = ctx->state;

	/*
	 * State rows are modified as follows:
	 *
	 * state[0] = { a0, a1, a2, a3 }->{ a0, a1, a2, a3 }
	 * state[1] = { a0, a1, a2, a3 }->{ a1, a2, a3, a0 }
	 * state[2] = { a0, a1, a2, a3 }->{ a2, a3, a0, a1 }
	 * state[3] = { a0, a1, a2, a3 }->{ a3, a0, a1, a2 }
	 *
	 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	s[1] = s[1] >> 8 | s[1] << 24;
	s[2] = s[2] >> 16 | s[2] << 16;
	s[3] = s[3] << 8 | s[3] >> 24;
#elif __BYTE_ORDER == __BIG_ENDIAN
	s[1] = s[1] << 8 | s[1] >> 24;
	s[2] = s[2] << 16 | s[2] >> 16;
	s[3] = s[3] >> 8 | s[3] << 24;
#else
#error unsupported byte order
#endif
}

/* Does cyclical shift in state columns reciprocal of shift_rows(). */
static void
inv_shift_rows(struct aes_context *ctx)
{
	u_int32_t *s = ctx->state;

	/*
	 * State rows are modified as follows:
	 *
	 * state[0] = { a0, a1, a2, a3 }->{ a0, a1, a2, a3 }
	 * state[1] = { a0, a1, a2, a3 }->{ a3, a0, a1, a2 }
	 * state[2] = { a0, a1, a2, a3 }->{ a2, a3, a0, a1 }
	 * state[3] = { a0, a1, a2, a3 }->{ a1, a2, a3, a0 }
	 *
	 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	s[1] = s[1] << 8 | s[1] >> 24;
	s[2] = s[2] << 16 | s[2] >> 16;
	s[3] = s[3] >> 8 | s[3] << 24;
#elif __BYTE_ORDER == __BIG_ENDIAN
	s[1] = s[1] >> 8 | s[1] << 24;
	s[2] = s[2] >> 16 | s[2] << 16;
	s[3] = s[3] << 8 | s[3] >> 24;
#else
#error unsupported byte order
#endif
}

/* Multiplies columns of the state by fixed polynomial in GF(2^8). */
static void
mix_columns(struct aes_context *ctx)
{
	u_int8_t *s0, *s1, *s2, *s3;
	u_int8_t n0, n1, n2, n3;
	u_int8_t *sp;
	int i, nb;

	nb = ctx->nb;
	sp = (u_int8_t *) ctx->state;

	s0 = sp + (nb*0);
	s1 = sp + (nb*1);
	s2 = sp + (nb*2);
	s3 = sp + (nb*3);

	for (i = 0; i < nb; i++) {
		/* Calculate matrix multiplication. */
		n0 = galois_mul(0x2, *s0) ^ galois_mul(0x3, *s1) ^ *s2 ^ *s3;
		n1 = *s0 ^ galois_mul(0x2, *s1) ^ galois_mul(0x3, *s2) ^ *s3;
		n2 = *s0 ^ *s1 ^ galois_mul(0x2, *s2) ^ galois_mul(0x3, *s3);
		n3 = galois_mul(0x3, *s0) ^ *s1 ^ *s2 ^ galois_mul(0x2, *s3);
		/* Store results into state and skip to next column. */
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}

/* Multiplies columns of the state by fixed polynomial in GF(2^8) using inverted matrix. */
static void
inv_mix_columns(struct aes_context *ctx)
{
	u_int8_t *s0, *s1, *s2, *s3;
	u_int8_t n0, n1, n2, n3;
	u_int8_t *sp;
	int i, nb;

	nb = ctx->nb;
	sp = (u_int8_t *) ctx->state;

	s0 = sp + (nb*0);
	s1 = sp + (nb*1);
	s2 = sp + (nb*2);
	s3 = sp + (nb*3);

	for (i = 0; i < nb; i++) {
		/* Calculate matrix multiplication. */
		n0 = galois_mul(0xe, *s0) ^ galois_mul(0xb, *s1) ^
		     galois_mul(0xd, *s2) ^ galois_mul(0x9, *s3);
		n1 = galois_mul(0x9, *s0) ^ galois_mul(0xe, *s1) ^
		     galois_mul(0xb, *s2) ^ galois_mul(0xd, *s3);
		n2 = galois_mul(0xd, *s0) ^ galois_mul(0x9, *s1) ^
		     galois_mul(0xe, *s2) ^ galois_mul(0xb, *s3);
		n3 = galois_mul(0xb, *s0) ^ galois_mul(0xd, *s1) ^
		     galois_mul(0x9, *s2) ^ galois_mul(0xe, *s3);
		/* Store results into state and skip to next column. */
		*s0++ = n0;
		*s1++ = n1;
		*s2++ = n2;
		*s3++ = n3;
	}
}

DEBUG_ONLY(

static void
print_state(struct aes_context *ctx, const char *prefix, int round)
{
	int i;
	u_int8_t *sp;

	if (prefix != NULL)
		printf("%s[%2d]: ", prefix, round);

	sp = (u_int8_t *) ctx->state;

	for (i = 0; i < ctx->nb; i++) {
		printf("%02x%02x%02x%02x",
		       sp[0], sp[4], sp[8], sp[12]);
		++sp;
	}

	printf("\n");
}

static void
print_ksched(struct aes_context *ctx, const char *prefix, int round)
{
	int i;
	u_int32_t *ks;

	ks = ctx->w + (round * ctx->nb);

	if (prefix != NULL)
		printf("%s[%2d]: ", prefix, round);

	for (i = 0; i < ctx->nb; i++) {
		u_int8_t *sp = (u_int8_t *)(ks + i);
		printf("%02x%02x%02x%02x",
		       sp[0], sp[1], sp[2], sp[3]);
		sp += sizeof(u_int32_t);
	}

	printf("\n");
}

) /* DEBUG_ONLY */

void
aes_init()
{
	static int aes_initialized;

	if (aes_initialized)
		return;

	galois_init_tables();

	rijndael_sbox_init();

	aes_initialized = TRUE;
}

struct aes_context *
aes_context_new()
{
	struct aes_context *ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));

	ctx->klen = AES_KEY_UNKNOWN;
	ctx->nr = -1;
	ctx->nb = -1;
	ctx->nk = -1;

	return ctx;
}

void
aes_context_free(struct aes_context **ctx)
{
	return_if_fail(ctx != NULL);
	return_if_fail(*ctx != NULL);

	/* Zero out sensitive data before returning it to allocator. */
	memset((*ctx)->key, 0, sizeof((*ctx)->key));
	memset((*ctx)->w, 0, sizeof((*ctx)->w));

	free(*ctx);
	*ctx = NULL;
}

int
aes_set_key(struct aes_context *ctx, const void *key, aes_key_len_t klen)
{
	int nr, nbytes;

//	aes_key_len_t klen;

//	klen = AES_KLEN;

	return_val_if_fail(ctx != NULL, -1);

	switch (klen) {
	case AES_KEY_128:
		nbytes = 16;
		nr = 10;
		break;
	case AES_KEY_192:
		nbytes = 24;
		nr = 12;
		break;
	case AES_KEY_256:
		nbytes = 32;
		nr = 14;
		break;
	default:
		return -1;
	}

	ctx->klen = klen;
	ctx->nb = AES_NB;
	ctx->nk = nbytes / sizeof(u_int32_t);
	/* 10, 12 or 14 rounds */
	ctx->nr = nr;

	/* Save key into context. */
	memcpy(ctx->key, key, nbytes);

	/* Copy key into first words of expanded key. */
	memcpy(ctx->w, ctx->key, nbytes);

	/* Perform key expansion. */
	key_expansion(ctx);

	return 0;
}

void
aes_encrypt(struct aes_context *ctx, const u_int8_t *in, u_int8_t *out)
{
	u_int8_t *sp;
	int i, nr;

	return_if_fail(ctx != NULL);
	return_if_fail(in != NULL && out != NULL);

	sp = (u_int8_t *) ctx->state;
	nr = ctx->nr;

	/* Copy input block into state. */
	for (i = 0; i < 16; i++) {
		int x, y;
		x = i % 4;
		y = i >> 2; 
		sp[x*4 + y] = in[y*4 + x];
	}

	DEBUG_ONLY(print_state(ctx, "input", 0));
	DEBUG_ONLY(print_ksched(ctx, "k_sch", 0));

	/* Encrypt state. */
	add_round_key(ctx, 0);

	for (i = 1; i <= nr-1; i++) {

		DEBUG_ONLY(print_state(ctx, "start", i));
		/* Substitute state bytes using S-Box. */
		sub_bytes(ctx);

		DEBUG_ONLY(print_state(ctx, "s_box", i));
	
		/* Cyclical shift state rows. */
		shift_rows(ctx);
		
		DEBUG_ONLY(print_state(ctx, "s_row", i));
		
		/* Do polynomial matrix multiplication. */
		mix_columns(ctx);
		
		DEBUG_ONLY(print_state(ctx, "m_col", i));
		DEBUG_ONLY(print_ksched(ctx, "k_sch", i));

		/* XOR state with scheduled key. */
		add_round_key(ctx, i);
	}

	DEBUG_ONLY(print_state(ctx, "start", i));

	sub_bytes(ctx);
	
	DEBUG_ONLY(print_state(ctx, "s_box", i));
	
	shift_rows(ctx);

	DEBUG_ONLY(print_state(ctx, "s_row", i));
	DEBUG_ONLY(print_ksched(ctx, "k_sch", i));

	add_round_key(ctx, i);

	DEBUG_ONLY(print_state(ctx, "output", i));

	/* Copy state to output. */
	for (i = 0; i < 16; i++) {
		int x, y;
		x = i % 4;
		y = i >> 2;
		out[y*4 + x] = sp[x*4 + y];
	}
}

void
aes_decrypt(struct aes_context *ctx, const u_int8_t *in, u_int8_t *out)
{
	u_int8_t *sp;
	int i, nr;

	return_if_fail(ctx != NULL);
	return_if_fail(in != NULL && out != NULL);

	sp = (u_int8_t *) ctx->state;
	nr = ctx->nr;

	/* Copy input block into state. */
	for (i = 0; i < 16; i++) {
		int x, y;
		x = i % 4;
		y = i >> 2; 
		sp[x*4 + y] = in[y*4 + x];
	}

	DEBUG_ONLY(print_state(ctx, "iinput", 0));
	DEBUG_ONLY(print_ksched(ctx, "ik_sch", 0));

	/* Encrypt state. */
	add_round_key(ctx, nr);

	for (i = nr-1; i > 0; i--) {

		DEBUG_ONLY(print_state(ctx, "istart", nr-i));
		
		inv_shift_rows(ctx);

		DEBUG_ONLY(print_state(ctx, "is_row", nr-i));

		inv_sub_bytes(ctx);

		DEBUG_ONLY(print_state(ctx, "is_box", nr-i));
		DEBUG_ONLY(print_ksched(ctx, "ik_sch", nr-i));

		add_round_key(ctx, i);

		inv_mix_columns(ctx);

		DEBUG_ONLY(print_state(ctx, "im_col", nr-i));
	}

	inv_shift_rows(ctx);

	DEBUG_ONLY(print_state(ctx, "is_row", nr));

	inv_sub_bytes(ctx);

	DEBUG_ONLY(print_state(ctx, "is_box", nr));
	DEBUG_ONLY(print_ksched(ctx, "ik_sch", nr));

	add_round_key(ctx, 0);

	DEBUG_ONLY(print_state(ctx, "ioutput", nr));

	/* Copy state to output. */
	for (i = 0; i < 16; i++) {
		int x, y;
		x = i % 4;
		y = i >> 2;
		out[y*4 + x] = sp[x*4 + y];
	}
}

