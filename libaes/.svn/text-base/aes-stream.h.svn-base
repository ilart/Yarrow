#ifndef AES_STREAM_H_
#define AES_STREAM_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	AES_STREAM_MODE_INVALID = 0,
	AES_STREAM_MODE_OFB,		/* Output Feedback */
	AES_STREAM_MODE_CFB,		/* Cipher Feedback */
	/* default mode */
	AES_STREAM_MODE_DEFAULT = AES_STREAM_MODE_OFB
} aes_stream_mode_t;

/* 
 * Prototypes of generic encrypt/decrypt functions.
 *
 * Each function obtains it's context and pointers to input and output
 * buffers each of block size used by cipher. For example AES block can be 128,
 * 192 or 256 bits. Input is processed according to encryption/decryption algorithm
 * and written to output buffer.
 *
 */
typedef void (*aes_encrypt_func)(void *ctx, const void *in, void *out);
typedef void (*aes_decrypt_func)(void *ctx, const void *in, void *out);

/* Opaque stream cipher structure. */
struct aes_stream;

/* Creates new stream cipher using encryption/decryption functions, specified
 * block length and block cipher context. This context is passed to
 * encrypt/decrypt functions as a first argument.
 */
struct aes_stream *aes_stream_create(aes_encrypt_func encrypt, aes_decrypt_func decrypt, size_t blen, void *ctx);

/* Destroys stream cipher. */
void aes_stream_destroy(struct aes_stream **stream);

/* Sets stream cipher mode. */
int aes_stream_set_mode(struct aes_stream *stream, aes_stream_mode_t mode);

/* Sets Initialization Vector (IV) for the stream cipher. */
void aes_stream_set_iv(struct aes_stream *stream, void *iv);

/* Encrypts block of arbitrary length `len' pointed by `data' in-place. */
void aes_stream_encrypt(struct aes_stream *stream, void *data, size_t len);

/* Decrypts block of arbitrary length `len' pointed by `data' in-place. */
void aes_stream_decrypt(struct aes_stream *stream, void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif

