/* 
 * GOST 28147-89 block cipher implementation.
 *
 * Copyright (C) 2011, Grisha Sitkarev
 * <sitkarev@unixkomi.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"

#include "macros.h"
#include "gost.h"

#define GOST_GAMMA_C1		0x01010101U
#define GOST_GAMMA_C2		0x01010104U
#define GOST_2EXP32M1		0xFFFFFFFFU /* 2^32 - 1 */

#define GAMMA_LEFT(x)		((x)->head - (x)->tail)

/* Well-known S-box used by Central Bank of Russia. */
static u_int8_t sbox_default[] = {
	4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3,
	14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9,
	5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11,
	7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3,
	6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2,
	4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14,
	13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12,
	1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12
};

struct gost_context {
	/* GOST 256 bit key */
	u_int32_t	key[8];

	/* current gamma */
	u_int8_t	gamma[8];
	/* pointers to gamma buffer */
	u_int8_t	*tail;
	u_int8_t	*head;

	/* substitution box 8x16 */
	u_int8_t	*sbox;
};

static void gost_basic(u_int32_t *lo, u_int32_t *hi, u_int32_t key, const u_int8_t *sbox);
void gost_encrypt_32z(struct gost_context *ctx, u_int32_t *block);
void gost_decrypt_32r(struct gost_context *ctx, u_int32_t *block);

struct gost_context *
gost_context_new()
{
	struct gost_context *ctx;

	ctx = malloc(sizeof(*ctx));

	if (ctx == NULL)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));

#if _POSIX_MEMLOCK > 0
	mlock(ctx, sizeof(*ctx));
#else
#warning Your system has no mlock() function. Sensitive information may leak into swap file!
#endif
	ctx->sbox = sbox_default;
	ctx->tail = ctx->head = ctx->gamma;

	return ctx;
}

void
gost_context_free(struct gost_context **ctx)
{
	return_if_fail(ctx != NULL);
	return_if_fail(*ctx != NULL);

	if ((*ctx)->sbox != sbox_default) {
		assert((*ctx)->sbox != NULL);
		free((*ctx)->sbox);
	}

#if _POSIX_MEMLOCK > 0
	munlock(*ctx, sizeof(**ctx));
#endif
	memset(*ctx, 0, sizeof(**ctx));
	free(*ctx);
	*ctx = NULL;
}

int
gost_set_sbox(struct gost_context *ctx, const u_int8_t *sbox)
{
	return_val_if_fail(ctx != NULL, -1);

	/* Did user requested S-box update? */
	if (ctx->sbox != NULL && ctx->sbox != sbox_default)
		free(ctx->sbox);

	if (sbox != NULL) {
		ctx->sbox = malloc(GOST_SBOX_NELEMS);
		if (ctx->sbox == NULL)
			return -1;
		memcpy(ctx->sbox, sbox, GOST_SBOX_NELEMS);
	} else {
		ctx->sbox = sbox_default;
	}

	return 0;
}

void
gost_set_key(struct gost_context *ctx, const u_int32_t *key)
{
	return_if_fail(ctx != NULL);
	return_if_fail(key != NULL);

	memcpy(ctx->key, key, GOST_KEY_NELEMS * sizeof(u_int32_t));
}

void
gost_set_sync(struct gost_context *ctx, const u_int32_t *sync)
{
	return_if_fail(ctx != NULL);
	return_if_fail(sync != NULL);

	memcpy(ctx->gamma, sync, sizeof(ctx->gamma));

	ctx->head = ctx->tail = ctx->gamma;

	gost_encrypt_32z(ctx, (u_int32_t *)ctx->gamma);
}

/*-----------------------------------------------------------*/

static inline void
gost_basic(u_int32_t *lo, u_int32_t *hi, u_int32_t key, const u_int8_t *sbox)
{
	u_int32_t s;

#define SBOX(x, n)	(sbox[(n << 2) + ((x >> n) & 0xf)] << n)

	/* S = (N_1 + X) mod 2^32 */
	s = *lo + key;

	/* S = H(s) */
	s  = SBOX(s, 0)  | SBOX(s, 4)  | SBOX(s, 8)  | SBOX(s, 12) |
	     SBOX(s, 16) | SBOX(s, 20) | SBOX(s, 24) | SBOX(s, 28);

	/* S = R(s) <- 11 */
	s = (s << 11) | (s >> 21);

	/* S = S (+) N_2 */
	s ^= *hi;

	/* N_2 = N_1, N_1 = S */
	*hi = *lo;
	*lo = s;
}

void
gost_encrypt_32z(struct gost_context *ctx, u_int32_t *block)
{
	int ksched[32] = {
		0, 1, 2, 3, 4, 5, 6, 7, 
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0
	};
	u_int32_t *lo, *hi, tmp;
	int i, x;

	lo = block;
	hi = lo + 1;

	for (i = 0; i < ARRAY_SIZE(ksched); i++) {
		x = ksched[i];
		gost_basic(lo, hi, ctx->key[x], ctx->sbox);
	}

	tmp = *lo;
	*lo = *hi;
	*hi = tmp;
}

void
gost_decrypt_32r(struct gost_context *ctx, u_int32_t *block)
{
	int ksched[32] = {
		0, 1, 2, 3, 4, 5, 6, 7,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0
	};
	u_int32_t *lo, *hi, tmp;
	int i, x;

	lo = block;
	hi = lo + 1;

	for (i = 0; i < ARRAY_SIZE(ksched); i++) {
		x = ksched[i];
		gost_basic(lo, hi, ctx->key[x], ctx->sbox);
	}

	tmp = *lo;
	*lo = *hi;
	*hi = tmp;
}

#if defined __x86_64 || defined __x86_32
static inline void
gost_update_gamma(struct gost_context *ctx)
{
	u_int32_t *p;

	p = (u_int32_t *) ctx->gamma;

	p[0] += GOST_GAMMA_C1;

	__asm__ __volatile__(
		"    addl %%ebx,%%eax\n"
		"    adcl $0,%%eax\n"
		:"=a"(p[1])
		:"a"(p[1]),"b"(GOST_GAMMA_C2)
	);
}
#else
static inline void
gost_update_gamma(struct gost_context *ctx)
{
	u_int32_t *p;
	int c, oflag;	/* overflow flag */

	p = (u_int32_t *) ctx->gamma;

	p[0] += GOST_GAMMA_C1;

	c = GOST_2EXP32M1 - p[1];
	oflag = (GOST_GAMMA_C2 > c) ? 1 : 0;
	p[1] += GOST_GAMMA_C2;
	p[1] += oflag;
}
#endif

void
gost_apply_gamma(struct gost_context *ctx, void *data, int len)
{
	u_int8_t *p;
	int i, n;

	return_if_fail(ctx != NULL);
	return_if_fail(data != NULL);

	p = data;

	while (len > 0) {

		if ((n = GAMMA_LEFT(ctx)) == 0) {
			gost_update_gamma(ctx);
			gost_encrypt_32z(ctx, (u_int32_t *)ctx->gamma);
			ctx->tail = ctx->gamma;
			ctx->head = ctx->gamma + sizeof(ctx->gamma);
			n = GOST_BLOCK_LEN;
		}

		n = (n > len) ? len : n;

		for (i = 0; i < n; i++)
			*p++ ^= *ctx->tail++;

		len -= n;
	}
}

