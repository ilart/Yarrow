
#ifndef __CIPHER_DESC_H
#define __CIPHER_DESC_H

#include "macros.h"
#include "common.h"
#include "gost.h"
#include "aes.h"

#define CIPHER_GOST	"gost"
#define CIPHER_AES	"aes"

union _cipher_ctx {
	struct gost_context gost; 
//	struct aes_context aes;
};

struct cipher_desc {

	const char *name;

	int block_size;

	/*key size in bytes*/
	int key_size;

	/* function of creat context*/
	void *(*context_new)();

	/* function of encrypt */
	void (*encrypt)(void *ctx, void *block);

	/* function of decrypt*/
	void (*decrypt)(void *ctx, void *block);

	/* fuction deinit context*/
	void (*context_free)(void **ctx);

	/* function set key into context ctx*/
	void (*set_key)(void *ctx, void *key);
};

struct cipher_desc *cipher_desc_get(const char *cipher_name);
#endif	
