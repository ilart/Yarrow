#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "macros.h"
#include "aes.h"
#include "galois.h"
#include "sbox.h"

/* Key values given by FIPS-192 Appendix A. */
void
show_key_schedule()
{
	struct aes_context *ctx;
	char *key_str[] = { "AES_128", "AES_192", "AES_256" };
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
	int i;

	for (i = 0; i < 3; i++) {
		printf("Testing: %s\n", key_str[i]);
		ctx = aes_context_new();
		aes_set_key(ctx, keys[i], key_type[i]);
		aes_context_free(&ctx);
	}
}

/* Key and message values given by FIPS-192 Appendix B. */
void
test_lib()
{
	unsigned char out[16];
	unsigned char iout[16];
	/* Reference message subject to encryption. */
	unsigned char msg[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	/* Encryption/decryption keys. */
	unsigned char key128[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char key192[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	unsigned char key256[] = { 
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,	0x1c, 0x1d, 0x1e, 0x1f };
	/* Reference encrypted msg output for 128, 192 and 256 bit keys. */
	unsigned char out128[] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
	unsigned char out192[] = {
		0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
		0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
	unsigned char out256[] = {
		0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
		0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
	unsigned char *key[] = { key128, key192, key256 };
	unsigned char *encmsg[] = { out128, out192, out256 };
	char *key_str[] = { "key128", "key192", "key256" };
	unsigned int key_type[] = { AES_KEY_128, AES_KEY_192, AES_KEY_256 };
	struct aes_context *ctx;
	int i;

	for (i = 0; i < 3; i++) {
		printf("\n");
		printf("State: %s\n", key_str[i]);

		ctx = aes_context_new();
		aes_set_key(ctx, key[i], key_type[i]);

		printf("CIPHER (ENCRYPT): ");
		aes_encrypt(ctx, msg, out);

		if (memcmp(out, encmsg[i], sizeof(msg)) != 0) {
			fprintf(stderr, "Warning!!! encrypt test failed for %s\n", key_str[i]);
			goto next;
		} else
			printf("OK\n");

		printf("INVERSE CIPHER (DECRYPT): ");
		aes_decrypt(ctx, out, iout);

		if (memcmp(msg, iout, sizeof(msg)) != 0)
			fprintf(stderr, "Warning!!! decrypt test failed for %s\n", key_str[i]);
		else
			printf("OK\n");
next:
		aes_context_free(&ctx);
	}
}

int opt_show_ksch;	/* print key schedule */
int opt_show_vec;	/* test encrypt/decrypt and print cipher state vector and key schedule */
int opt_show_sbox; 	/* print S-Box and it's inverse */
int opt_show_galois;	/* print Galois GF(2^8) tables */

#define PRTCHAR(c)	(isprint(c) ? (c) : '?')

int
main(int argc, char *argv[])
{
	int opt;

	opterr = 0;

	while ((opt = getopt(argc, argv, "gksv")) != -1) {
		switch (opt) {
		case 'v':
			++opt_show_vec;
			break;
		case 'g':
			++opt_show_galois;
			break;
		case 'k':
			++opt_show_ksch;
			break;
		case 's':
			++opt_show_sbox;
			break;
		default:
			printf("unknown option -%c\n", PRTCHAR(optopt));
			printf("Usage: %s [OPTIONS]\n", argv[0]);
			exit(1);
		}
	}

	aes_init();

	if (opt_show_galois)
		galois_print_tables();

	if (opt_show_sbox)
		rijndael_sbox_print();

	if (opt_show_ksch)
		show_key_schedule();

	if (opt_show_vec)
		test_lib();

	return 0;
}

