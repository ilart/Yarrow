#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "macros.h"
#include "aes.h"
#include "aes-stream.h"

int
main(int argc, char *argv[])
{
	int key_type[] = { AES_KEY_128, AES_KEY_192, AES_KEY_256 };
	unsigned char key256[] = 
		{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
	unsigned char key192[] = 
		{ 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		  0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		  0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
	unsigned char key128[] =
		{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	unsigned char *keys[] = { key128, key192, key256 };
	
	u_int8_t iv[] =
		{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		  0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
	u_int8_t iv2[] = 
		{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		  0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };

	int i;
	
	struct aes_context *ci, *co;
	struct aes_stream *si, *so;

	aes_init();

	ci = aes_context_new();
	co = aes_context_new();

	si = aes_stream_create((aes_encrypt_func)aes_encrypt, (aes_decrypt_func)aes_decrypt, 16, ci);
	so = aes_stream_create((aes_encrypt_func)aes_encrypt, (aes_decrypt_func)aes_decrypt, 16, co);
	
	aes_stream_set_iv(si, iv);
	aes_stream_set_iv(so, iv2);
	aes_stream_set_mode(si, AES_STREAM_MODE_OFB);
	aes_stream_set_mode(so, AES_STREAM_MODE_OFB);

	for (i = 0; i < 3; i++) {
		int n;
		char msg[] = "У лукоморья дуб зелёный,\n";
		char msg2[] = "Златая цепь на дубе том.\n";
		char msg3[] = "И днём и ночью кот учёный...\n";

		aes_set_key(ci, keys[i], key_type[i]);
		aes_set_key(co, keys[i], key_type[i]);

		aes_stream_encrypt(si, msg, (n = strlen(msg)));
		aes_stream_decrypt(so, msg, n);
		printf("%s", msg);

		aes_stream_encrypt(si, msg2, (n = strlen(msg2)));
		aes_stream_decrypt(so, msg2, n);
		printf("%s", msg2);

		aes_stream_encrypt(si, msg3, (n = strlen(msg3)));
		aes_stream_decrypt(so, msg3, n);
		printf("%s", msg3);
	}

	aes_stream_set_iv(si, iv);
	aes_stream_set_iv(so, iv);
	aes_stream_set_mode(si, AES_STREAM_MODE_CFB);
	aes_stream_set_mode(so, AES_STREAM_MODE_CFB);

	for (i = 0; i < 3; i++) {
		int n;
		char msg[] = "Всё ходит по цепи кругом,\n";
		char msg2[] = "Идёт направо -- песнь заводит,\n";
		char msg3[] = "Налево -- сказку говорит.\n";

		aes_set_key(ci, keys[i], key_type[i]);
		aes_set_key(co, keys[i], key_type[i]);

		aes_stream_encrypt(si, msg, (n = strlen(msg)));
		aes_stream_decrypt(so, msg, n);
		printf("%s", msg);

		aes_stream_encrypt(si, msg2, (n = strlen(msg2)));
		aes_stream_decrypt(so, msg2, n);
		printf("%s", msg2);

		aes_stream_encrypt(si, msg3, (n = strlen(msg3)));
		aes_stream_decrypt(so, msg3, n);
		printf("%s", msg3);
	}

	aes_stream_destroy(&si);
	aes_stream_destroy(&so);
	aes_context_free(&ci);
	aes_context_free(&co);

	return 0;
}

