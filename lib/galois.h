#ifndef GALOIS_H_
#define GALOIS_H_

/*
 * Basic GF(2^8) routines.
 */

/* Add, subtract and multiply. */
u_int8_t galois_add(u_int8_t a, u_int8_t b);
u_int8_t galois_sub(u_int8_t a, u_int8_t b);
u_int8_t galois_mul_slow(u_int8_t a, u_int8_t b);

/* 
 * These following functions requires galois_init_tables() before usage and use
 * table lookups which is faster then galois_mul_slow() and has constant
 * execution time.
 */

/* returns (a * b) */
u_int8_t galois_mul(u_int8_t a, u_int8_t b);

/* returns (a / b) */
u_int8_t galois_div(u_int8_t a, u_int8_t b);

/* returns (1 / a) */
u_int8_t galois_mul_inverse(u_int8_t a);

void galois_init_tables();
void galois_print_tables();

#endif

