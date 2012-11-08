#ifndef AES_CBC_H_
#define AES_CBC_H_

struct aes_cbc {
	uint8_t		iv[16];		/* IV and previous ciphertext are stored here */
	uint8_t		buffer[16];	/* partial input */
	unsigned int	len;		/* length of partial input */
	int		mode;		/* CBC_ENCRYPT or CBC_DECRYPT */

	/* block cipher encoding routine */
	void (*encode)(void *ctx, const void *in, void *out);
	/* block cipher context */
	void		*ctx;
};

void aes_cbc_init(struct aes_cbc *cbc,
		  void (*encode)(void *ctx, const void *in, void *out),
		  void *ctx, int encr, const unsigned char iv[16]);

void aes_cbc_update(struct aes_cbc *cbc, void *out, unsigned *olen, const void *in, unsigned ilen);

void aes_cbc_final(struct aes_cbc *cbc, void *out, unsigned *olen);

#endif

