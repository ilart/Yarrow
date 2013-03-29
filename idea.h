#ifndef _IDEA_H
#define _IDEA_H

#define IDEA_KEY_NELEMS 8 /*number of 16-bit keyword (8*16 = 128). IDEA use 128 bit key*/
#define IDEA_BLOCK_NBYTES 4 /*number of 16-bit block (4*16 = 64). IDEA use 64 bit block*/
#define IDEA_ROUND_KEY_NELEMS 52 /*number of round key*/ 

#define CRLF "\r\n"

struct idea_context 
{
	u_int16_t tabl_key[IDEA_ROUND_KEY_NELEMS];
	u_int16_t key[IDEA_KEY_NELEMS];
};

struct idea_context *idea_context_new();
void idea_context_free(struct idea_context **ctx);
void idea_set_key(struct idea_context *ctx, u_int16_t *key);
void idea_encrypt(struct idea_context *enc, u_int16_t *block);
void idea_decrypt(struct idea_context *dec, u_int16_t *block)

u_int16_t mulinv(u_int16_t x);
u_int16_t addinv(u_int16_t x);

#endif
