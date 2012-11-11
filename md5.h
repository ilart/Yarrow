#ifndef MD5_H_
#define MD5_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_LEN 64

struct md5_context {
	u_int32_t	nbits[2];	/* message size (in bits) */
	u_int32_t	state[4];	/* state words */
	u_int8_t	buffer[64];	/* message buffer */
};

/* Initializes MD5 context. */
void md5_context_init(struct md5_context *ctx);

/* Updates MD5 context with a new portion of message data. */
void md5_update(struct md5_context *ctx, const void *msg, u_int32_t msglen);

/* Produces message digest. */
void *md5_final(struct md5_context *ctx, unsigned char digest[16]);

#ifdef __cplusplus
}
#endif

#endif

