#ifndef WHIRLPOOL_H_
#define WHIRLPOOL_H_

struct whirlpool_context {
        uint8_t         buffer[64];     /* 512-bit message buffer */
        uint32_t        count[2];       /* data length counter */
        uint64_t        state[8];       /* 8x8 state matrix */
};

void whirlpool_context_init(struct whirlpool_context *ctx);
void whirlpool_update(struct whirlpool_context *ctx, const void *msg, uint32_t len);
void whirlpool_final(struct whirlpool_context *ctx, unsigned char digest[64]);

#endif

