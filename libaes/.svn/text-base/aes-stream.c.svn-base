/*
 * AES Block Cipher Modes of Operation.
 *
 * This code implements CFB and OFB modes used to turn block cipher
 * into stream cipher.
 *
 * Grisha Sitkarev, <sitkarev@unixkomi.ru> 2011 (c)
 *
 */
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "macros.h"
#include "aes-stream.h"

#define IV_LEN_MAX	16	/* maximum length of initialization vector */

#define IV_LEFT(s)	((s)->head - (s)->tail)

typedef void (*stream_encrypt_func)(struct aes_stream *s, void *data, size_t len);
typedef void (*stream_decrypt_func)(struct aes_stream *s, void *data, size_t len);

struct aes_stream {
	aes_stream_mode_t	mode;		/* streaming mode */
	size_t			blen;		/* cipher block length */
	void			*ctx;		/* block cipher context */
	aes_encrypt_func	encrypt;	/* block cipher encryption routine */
	aes_decrypt_func	decrypt;	/* block cipher decryption routine */
	u_int8_t		iv[IV_LEN_MAX];	/* initialization vector */
	u_int8_t		*tail;		/* start of iv buffer */
	u_int8_t		*head;		/* end of iv buffer */
	stream_encrypt_func	stream_encrypt; /* stream cipher encryptor */
	stream_decrypt_func	stream_decrypt;	/* stream cipher decryptor */
};

/* Known stream cipher mode implementations forward declarations. */
static void aes_stream_ofb(struct aes_stream *s, void *data, size_t len);
static void aes_stream_cfb_encrypt(struct aes_stream *s, void *data, size_t len);
static void aes_stream_cfb_decrypt(struct aes_stream *s, void *data, size_t len);

struct aes_stream *
aes_stream_create(aes_encrypt_func encrypt, aes_encrypt_func decrypt, size_t blen, void *ctx)
{
	struct aes_stream *s;

	if (blen > IV_LEN_MAX)
		return NULL;

	s = malloc(sizeof(*s));
	if (s == NULL)
		return NULL;
	memset(s, 0, sizeof(*s));
#if _POSIX_MEMLOCK > 0
	mlock(s->iv, blen);
#else
#warning You have no mlock() function. Sensitive data may leak into swap file!
#endif
	s->encrypt = encrypt;
	s->decrypt = decrypt;
	s->blen = blen;
	s->ctx = ctx;
	s->mode = AES_STREAM_MODE_DEFAULT;
	s->stream_encrypt = aes_stream_ofb;
	s->stream_decrypt = aes_stream_ofb;

	/* No sequence available yet. */
	s->tail = s->head = s->iv;

	return s;
}

void
aes_stream_destroy(struct aes_stream **s)
{
	return_if_fail(s != NULL && *s != NULL);
#if _POSIX_MEMLOCK > 0
	munlock((*s)->iv, (*s)->blen);
#endif
	memset((*s)->iv, 0, (*s)->blen);
	free(*s);
	*s = NULL;
}

int
aes_stream_set_mode(struct aes_stream *s, aes_stream_mode_t mode)
{
	return_val_if_fail(s != NULL, -1);

	switch (mode) {
	case AES_STREAM_MODE_OFB:
		s->mode = mode;
		s->stream_encrypt = aes_stream_ofb;
		s->stream_decrypt = aes_stream_ofb;
		break;
	case AES_STREAM_MODE_CFB:
		s->mode = mode;
		s->stream_encrypt = aes_stream_cfb_encrypt;
		s->stream_decrypt = aes_stream_cfb_decrypt;
		break;
	default:
		return -1;
	}

	return 0;
}

void
aes_stream_set_iv(struct aes_stream *s, void *iv)
{
	return_if_fail(s != NULL);
	return_if_fail(iv != NULL);

	memcpy(s->iv, iv, s->blen);

	s->tail = s->head = s->iv;
}

/* Block cipher Cipher Feedback (CFB) mode encryption. */
static void
aes_stream_cfb_encrypt(struct aes_stream *s, void *data, size_t len)
{
	int i, n;
	u_int8_t *p;

	p = data;

	while (len > 0) {
		
		if ((n = IV_LEFT(s)) == 0) {
			(*s->encrypt)(s->ctx, s->iv, s->iv);
			s->tail = s->iv;
			s->head = s->iv + s->blen;
			n = s->blen;
		}
		
		n = (n > len) ? len : n;

		for (i = 0; i < n; i++) {
			*p ^= *s->tail;
			*s->tail++ = *p++;
		}

		len -= n;
	}
}

/* Block cipher Cipher Feedback (CFB) mode decryption. */
static void
aes_stream_cfb_decrypt(struct aes_stream *s, void *data, size_t len)
{
	int i, n;
	u_int8_t *p;

	p = data;

	while (len > 0) {
		u_int8_t tmp;

		if ((n = IV_LEFT(s)) == 0) {
			(*s->encrypt)(s->ctx, s->iv, s->iv);
			s->tail = s->iv;
			s->head = s->iv + s->blen;
			n = s->blen;
		}

		n = (n > len) ? len : n;

		for (i = 0; i < n; i++) {
			tmp = *p;
			*p++ ^= *s->tail;
			*s->tail++ = tmp;
		}

		len -= n;
	}
}

/* Block cipher Output Feedback mode (OFB) encryption/decryption. */
static void
aes_stream_ofb(struct aes_stream *s, void *data, size_t len)
{
	int i, n;
	u_int8_t *p;

	p = data;

	while (len > 0) {

		if ((n = IV_LEFT(s)) == 0) {
			(*s->encrypt)(s->ctx, s->iv, s->iv);
			s->tail = s->iv;
			s->head = s->iv + s->blen;
			n = s->blen;
		}

		n = (n > len) ? len : n;

		for (i = 0; i < n; i++)
			*p++ ^= *s->tail++;

		len -= n;
	}
}

void
aes_stream_encrypt(struct aes_stream *s, void *data, size_t len)
{
	return_if_fail(s != NULL);
	return_if_fail(data != NULL);

	(*s->stream_encrypt)(s, data, len);
}

void
aes_stream_decrypt(struct aes_stream *s, void *data, size_t len)
{
	return_if_fail(s != NULL);
	return_if_fail(data != NULL);

	(*s->stream_decrypt)(s, data, len);
}

