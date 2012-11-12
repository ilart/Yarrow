#ifndef SHA256_H_
#define SHA256_H_

#define SHA256_DIGEST_LEN	32

struct sha256_context {
        uint8_t         buffer[64];     /* 512-bit message buffer */
        uint32_t        count[2];       /* data length counter */
        uint32_t        state[8];       /* H(i) hash state */
};

void sha256_context_init(struct sha256_context *ctx);
void sha256_update(struct sha256_context *ctx, const void *msg, uint32_t len);
void *sha256_final(struct sha256_context *ctx, unsigned char digest[32]);

#endif /* SHA256_H_ */ 

