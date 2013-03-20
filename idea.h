#define IDEA_KEY_NELEMS 8 /*number of 16-bit keyword (8*16 = 128). IDEA use 128 bit key*/
#define IDEA_ROUND_KEY_NELEMS 52 /*number of round key*/ 

#define CRLF "\r\n"
#define return_if_fail(expr) \
do { \
        if (!(expr)) { \
                fprintf(stderr, "file %s line %d %s(): expression `%s' failed" CRLF, \
                        __FILE__, \
                        __LINE__, \
                        __FUNCTION__, \
#expr); \
                return; \
} \
} while (0)

struct idea_context *idea_context_new();
void idea_context_free(struct idea_context **ctx);
void idea_get_key(u_int16_t *key, struct idea_context *ctx);

u_int16_t mulinv(u_int16_t x);
u_int16_t addinv(u_int16_t x);