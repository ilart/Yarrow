#include <stdio.h>
#include <stdlib.h>

#include "macros.h"

#define GENERATING_POLY	0x03	/* x + 1 */
#define RIJNDAEL_POLY	0x1b	/* 8 bits of irreduceable polynomial x^8 + X^4 + x^3 + x + 1 {01}{1b}. */

static u_int8_t exptab[256];
static u_int8_t logtab[256];

/*
 * Summation and subtraction of polynomials in GF(2^8) is
 * equal to bitwise XOR operation for both. Two functions
 * are used for clarity only.
 */

/* a + b in GF(2^8) field. */
u_int8_t
galois_add(u_int8_t a, u_int8_t b)
{
	return a ^ b;
}

/* a - b in GF(2^8) field. */
u_int8_t
galois_sub(u_int8_t a, u_int8_t b)
{
	return a ^ b;
}

/* a * b in GF(2^8) field. */
u_int8_t
galois_mul_slow(u_int8_t a, u_int8_t b)
{
	int high_bit_on;
	u_int8_t c;

	c = 0;

	while (b) {

		if (b & 0x1)
			c ^= a;

		high_bit_on = a & 0x80;
		a <<= 1;

		if (high_bit_on)
			a ^= RIJNDAEL_POLY;
		b >>= 1;
	}

	return c;
}

/* Fast multiplication using g(x) powers and logarithms. */
u_int8_t
galois_mul(u_int8_t a, u_int8_t b)
{
	int c, d; 

	/*
	 * The main idea behind this algorithm is the following:
	 *
	 * Values of generating polynomial exponentiated into powers
	 * from 0 to 255 iterate through all GF(2^8) values. We are
	 * going to use generating polynomial g(x)=x+1.
	 *
	 * Then if we summate a and b and exponentiate g(x):
	 * 	g^a * g^b = g^(a+b)
	 * and getting logarithm of it:
	 *	log(a) * log(b) = log(a+b mod 255)
	 * we get the result of a*b in GF(2^8).
	 *
	 * If we generate a table of exponents for g(x) and table of
	 * logarithms of g(x) we can easily multiply two numbers using
	 * lookups in these tables.
	 */

	if (a != 0 && b != 0) {
		c = logtab[a] + logtab[b];
		d = exptab[c % 255];
		return d;
	}
	
	return 0;
}

/* Fast division using table lookups. For details see galois_mul(). */
u_int8_t
galois_div(u_int8_t a, u_int8_t b)
{
	int c, d;

	if (a != 0 && b != 0) {
		c = 255 + (logtab[a] - logtab[b]);
		d = exptab[c % 255];
		return d;
	}

	return 0;
}

/* Multiplicative inverse using table lookups. */
u_int8_t
galois_mul_inverse(u_int8_t a)
{
	int c;
	
	/* This function calculates 1/x. Note that log(1) is 0. */

	if (a == 0)
		return 0;

	c = 255 - logtab[a];

	return exptab[c];
}


/* Fills exponent and logarithm tables using x+1 generating polynomial. */
void
galois_init_tables()
{
	int i;
	u_int8_t c;

	c = 1;

	for (i = 0; i < 256; i++) {
		logtab[c] = i;
		exptab[i] = c;
		c = galois_mul_slow(c, GENERATING_POLY);
	}
}

void
galois_print_tables()
{
	int i, j;
	int c, d;

	printf("g(x) = x + 1 in GF(2^8)\n");

	printf("Powers of g(x):\n");

	for (i = 0; i < 256; i += 16) {
		for (j = i; j < i+16; j++)
			printf(" %02X", exptab[j]);
		printf("\n");
	}

	printf("\n");

	printf("Logarithms of g(x):\n");

	for (i = 0; i < 256; i += 16) {
		for (j = i; j < i+16; j++)
			printf(" %02X", logtab[j]);
		printf("\n");
	}

	for (i = 0; i < 256; i++) {
		for (j = 0; j < 256; j++) {
			c = galois_mul_slow(i, j);
			d = galois_mul(i, j);
			if (c != d) {
				printf("Warning! i=%d*j=%d: mul=%02X mul_fast=%02X\n",
				       i, j, c, d);
			}
			c = galois_div(d, j);
			if (j != 0 && c != i)
				printf("Warning! div (i*j)/j NOT equal to i: c=%d i=%d j=%d\n", c, i, j);
		}
	}
}

