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

#ifndef GOST_H_
#define GOST_H_

#define GOST_SBOX_NELEMS	128	/* number of bytes in S-box table */
#define GOST_KEY_NELEMS		8	/* 32-bit key elements (256 bits) */
#define GOST_BLOCK_LEN		8	/* block length for 32z and 32r transforms */

struct gost_context;

struct gost_context *gost_context_new();

void gost_context_free(struct gost_context **ctx);

void gost_set_key(struct gost_context *ctx, const u_int32_t *key);

int gost_set_sbox(struct gost_context *ctx, const u_int8_t *sbox);

void gost_set_sync(struct gost_context *ctx, const u_int32_t *sync);

void gost_encrypt_32z(struct gost_context *ctx, u_int32_t *block);

void gost_decrypt_32r(struct gost_context *ctx, u_int32_t *block);

void gost_apply_gamma(struct gost_context *ctx, void *data, int len);

#endif /* GOST_H_ */

