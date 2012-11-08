/*
 * AES -- Advanced Encryption Standard (FIPS PUB 197).
 *
 * Implements encryption/decryption routines for 128, 192 and 256 keys.
 *
 * Grisha Sitkarev, <sitkarev@unixkomi.ru>, 2011 (c)
 */
#ifndef AES_H_
#define AES_H_

#define AES_BLOCK_NBYTES	16

enum {
	AES_NB		= 4,
	AES_NR_MAX	= 14
};

typedef enum {
	AES_KEY_UNKNOWN,
	AES_KEY_128,
	AES_KEY_192,
	AES_KEY_256
} aes_key_len_t;

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

/* Initialize static AES context structure. */
void aes_context_init(struct aes_context *ctx);

/* Cleanup static AES context structure. */
void aes_context_clean(struct aes_context *ctx);

/* Creates new AES cipher context. */
struct aes_context *aes_context_new();

/* Releases all resources associated with the context. */
void aes_context_free(struct aes_context **ctx);

/* Sets cipher key and it's type. */
int aes_set_key(struct aes_context *ctx, const void *key, aes_key_len_t klen);

/*
 * Note that encryption and decryption routines require user-alloced buffers
 * for input and output. Caller is responsible to provide at least 16 bytes
 * for them.
 */

/* Encrypts 128-bit data block `in' and produces ecrypted 128-bit output `out'. */
void aes_encrypt(struct aes_context *ctx, const u_int8_t *in, u_int8_t *out);

/* Decrypts 128-bit data block `in' and produces decrypted 128-bit output `out'.*/
void aes_decrypt(struct aes_context *ctx, const u_int8_t *in, u_int8_t *out);

#endif /* AES_H_ */

