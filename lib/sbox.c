#include <stdio.h>
#include <stdlib.h>

#include "macros.h"
#include "galois.h"

#define POLY_VECTOR	0x63
#define BYTE_ROL(x)	((x << 1) | (x >> 7))

/* Rijndael S-Box. */
unsigned char rijndael_sbox[256];

/* Rijndael inverse S-Box. */
unsigned char rijndael_isbox[256];

void
rijndael_sbox_init()
{
	int i, j;
	u_int8_t a, b;

	for (i = 0; i < 256; i++) {

		a = galois_mul_inverse(i);
		b = a;

		for (j = 0; j < 4; j++) {
			b = BYTE_ROL(b);
			a ^= b;
		}

		a ^= POLY_VECTOR;

		rijndael_sbox[i] = a;
		rijndael_isbox[a] = i;
	}
}

void
rijndael_sbox_print()
{
	int i, j;

	printf("Rijndael S-Box:\n");

	for (i = 0; i < 256; i += 16) {
		for (j = i; j <	i+16; j++) {
			printf(" %02X ", rijndael_sbox[j]);
		}
		printf("\n");
	}

	printf("Rijndael Inverse S-Box:\n");

	for (i = 0; i < 256; i += 16) {
		for (j = i; j <	i+16; j++) {
			printf(" %02X ", rijndael_isbox[j]);
		}
		printf("\n");
	}

}

