#ifndef __CIPHER_DESC_H
#define __CIPHER_DESC_H

struct cipher_desc {

	const char *name;

	int block_size;

	/* size of key in byts*/
	int key_size; 		 
	/* initialization function*/
	void (*init)(void *ctx);

	/* function of encrypt feeds context 'ctx' and block \
	 * of data 'block' which we want ecrypt*/
	void (*encrypt)(void *ctx, void *block);

	/* function set key into context ctx*/
	void (*set_key)(void *ctx, void *key);

	/* fuction deinit context*/
	void (*deinit)(void **ctx);
}

#endif	
