#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>

#include "idea.h"

static void idea_scrambling(struct idea_context *ctx, u_int16_t *block);
static void idea_invertkey(struct idea_context  *ctx);

static inline u_int16_t mul(u_int16_t a, u_int16_t b);
static inline u_int16_t sum(u_int16_t a, u_int16_t b);

struct idea_context 
{
	u_int16_t tabl_key[IDEA_ROUND_KEY_NELEMS];
	u_int16_t key[IDEA_KEY_NELEMS];
};

struct idea_context *
idea_context_new()
{
	struct idea_context *ctx;
	ctx = malloc(sizeof(*ctx));
	if(ctx == NULL)
		return NULL;
		
	memset(ctx, 0, sizeof(*ctx));
	
	
	return ctx;
}

void 
idea_encrypt(struct idea_context *enc, u_int16_t *block)
{
	idea_scrambling(enc, block);
}

void 
idea_decrypt(struct idea_context *dec, u_int16_t *block)
{
	idea_invertkey(dec);
	idea_scrambling(dec, block);
}

void
idea_context_free(struct idea_context **ctx)
{
	return_if_fail(ctx != NULL);
	return_if_fail(*ctx != NULL);
	
	assert(*ctx!=NULL);
	memset(*ctx, 0, sizeof(**ctx));
	free(*ctx);
	*ctx = NULL;
}

void 
idea_get_key(u_int16_t *key, struct idea_context *ctx)
{	
	return_if_fail(ctx != NULL);
	return_if_fail(key != NULL);
	
	int i;
	u_int16_t *enc_key = ctx->tabl_key;
	
	/*first 8 key will be the same */
	memcpy(enc_key, key, IDEA_KEY_NELEMS * sizeof(u_int16_t));
	
	/*The following key will be obtained by shifting the key by 25 bits to the left */
	for (i=8; i<IDEA_ROUND_KEY_NELEMS; i++) {
		if ((i & 7) < 6)
			enc_key[i]=(enc_key[i-7] & 127) << 9 | enc_key[i-6] >> 7;
		else if ((i & 7) == 6)
			enc_key[i]=(enc_key[i-7] & 127) << 9 | enc_key[i-14] >> 7;
		else
			enc_key[i]=(enc_key[i-15] & 127) << 9 | enc_key[i-14] >> 7;
	}
}

static void 
idea_invertkey(struct idea_context *ctx)
{
	return_if_fail(ctx != NULL);
	
	int t1, t2, t3, t4, round;
	u_int16_t *enc_key = ctx->tabl_key;
	u_int16_t tmp[52];
	 
	int i = 51;
	
	t1 = mulinv(*(enc_key++));
	t2 = addinv(*(enc_key++));
	t3 = addinv(*(enc_key++));
	t4 = mulinv(*(enc_key++));
	tmp[i--] = t4;
	tmp[i--] = t3;
	tmp[i--] = t2;
	tmp[i--] = t1;

	for (round = 0; round < 7; round++) {
		t1 = *(enc_key++);
		t2 = *(enc_key++);
		tmp[i--] = t2;
		tmp[i--] = t1;

		t1 = mulinv(*(enc_key++));
		t2 = addinv(*(enc_key++));
		t3 = addinv(*(enc_key++));
		t4 = mulinv(*(enc_key++));
		tmp[i--] = t4;
		tmp[i--] = t2;
		tmp[i--] = t3;
		tmp[i--] = t1;
	}
	t1 = *(enc_key++);
	t2 = *(enc_key++);
	tmp[i--] = t2;
	tmp[i--] = t1;

	t1 = mulinv(*(enc_key++));
	t2 = addinv(*(enc_key++));
	t3 = addinv(*(enc_key++));
	t4 = mulinv(*(enc_key++));
	tmp[i--] = t4;
	tmp[i--] = t3;
	tmp[i--] = t2;
	tmp[i--] = t1;
	
	memcpy(ctx->tabl_key, tmp, IDEA_ROUND_KEY_NELEMS * sizeof(u_int16_t));
}

static void 
idea_scrambling(struct idea_context *ctx, u_int16_t *block)
{			/*encryption algorithm*/
	return_if_fail(ctx != NULL);
	
	int k;
	u_int16_t tmp[3], a=0;
	u_int16_t *enc_key = ctx->tabl_key;

	for(k=0; k<8; k++){
		
		block[0] = mul(block[0], *(enc_key++));
		block[1] = sum(block[1], *(enc_key++));
		block[2] = sum(block[2], *(enc_key++));
		block[3] = mul(block[3], *(enc_key++));
		
		tmp[0] = block[0] ^ block[2];
		tmp[0] = mul(*(enc_key++), tmp[0]);
		
		tmp[1] = (block[1] ^ block[3]);
		tmp[1] = sum(tmp[0], tmp[1]);
		tmp[1] = mul(*(enc_key++), tmp[1]);
		
		
		tmp[2] = sum(tmp[0], tmp[1]);
		
		
		block[0] = block[0] ^ tmp[1];
		
		block[3] = block[3] ^ tmp[2];
		
		a = block[1] ^ tmp[2];
		block[1] = block[2] ^ tmp[1];
		block[2] = a;
		

	}
	block[0] = mul(block[0], *(enc_key++));
	a = block[1];
	block[1] = sum(block[2], *(enc_key++));
	block[2] = sum(a, *(enc_key++));
	block[3] = mul(block[3], *(enc_key++));
}

static inline u_int16_t mul(u_int16_t a, u_int16_t b)
{
	u_int32_t c;
	int r;
	
	if(a==0){
		r = 0x10001 - b;
	}else if(b==0){
		r = 0x10001 - a;
	}else{
		c = a * b;
		r = (c & 0xffff) - (c>>16);
		if (r<0){
			r += 0x10001;
		}
	}
	return r & 0xffff;
}

static inline u_int16_t sum(u_int16_t a, u_int16_t b)
{
	u_int16_t r;
	
	r = (a + b) & 0xffff;
	//printf("val %x+%x 0xffff = %x \n", a, b, r);
	return r;
}


u_int16_t 
addinv(u_int16_t x)
{
	x = 0x10000-x;
	return x;
}

u_int16_t 
mulinv(u_int16_t x)
{
	int r1, r, r2;
	int t1, t, t2;
	unsigned q;
	
	r2 = x;
	r1 = 0x10001;
	t1 = 0;
	t2 = 1;
	if(r2 < 2) {
		return r2;
	}
	while (r2 > 0) {
		q = r1 / r2;
		
		r = r1 - q*r2;
		r1 = r2;
		r2 = r;
		
		t = t1 - q*t2;
		t1 = t2;
		t2 = t;
	}
	if(t1<0)
		t1 = 0x10001+t1;
	
	return t1;
}

