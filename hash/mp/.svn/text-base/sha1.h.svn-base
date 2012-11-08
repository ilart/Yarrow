#ifndef SHA1_H_
#define SHA1_H_

#define SHA1_DIGEST_LEN	20

struct sha1_context {
        uint8_t         buffer[64];     /* 512-bit message buffer */
        uint32_t        count[2];       /* data length counter */
        uint32_t        state[5];       /* H(i) hash state */
};

void sha1_context_init(struct sha1_context *ctx);
void sha1_update(struct sha1_context *ctx, const void *msg, uint32_t len);
void sha1_final(struct sha1_context *ctx, unsigned char digest[20]);

#endif /* SHA1_H_ */ 

