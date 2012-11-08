/*
 * Multiple Precision Integer routines library.
 *
 * Grisha Sitkarev, 2011 (c)
 * <sitkarev@unixkomi.ru>
 *
 */

#ifndef MP_H_
#define MP_H_

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MP_OK	= 0,
	MP_ERR,
	MP_NOMEM,
	MP_COMPOSITE
};

#define MP_CMP_EQ	0
#define MP_CMP_GT	1
#define MP_CMP_LT	-1

#define MP_SIGN_POS	0
#define MP_SIGN_NEG	1

#define MP_INT_BASE	268435456
#define MP_INT_MASK	0x0FFFFFFF
#define MP_INT_BITS	28
#define MP_INT_BITS_ALL	32

typedef uint32_t _mp_int_t;
typedef uint64_t _mp_long_t;

/* Multiple precision integer structure. */
typedef struct mp_int {
	unsigned int	flags;
	unsigned int	alloc;	/* number of allocated digits */
	int		sign;	/* MP_SIGN_POS or MP_SIGN_NEG */
	int		top;	/* index to top digit */
	_mp_int_t	*dig;	/* malloc'ed array of digits */
} mp_int;

#define mp_iseven(x)	(mp_iszero(x) || (((x)->dig[0] & 0x1) == 0))
#define mp_isodd(x)	(((x)->top >= 0) && (((x)->dig[0] & 0x1) == 1))

void mp_dbg(const mp_int *a, FILE *fp);

/* Initializes MP integer. */
int mp_init(mp_int *a);

/* Releases all memory associated with MP integer. */
void mp_clear(mp_int *a);

/* Variable NULL-terminated list version of two routines above. */
int mp_initv(mp_int *a, ...);
void mp_clearv(mp_int *a, ...);

void mp_zero(mp_int *a);

int mp_iszero(const mp_int *a);
int mp_isone(const mp_int *a);
int mp_isneg(const mp_int *a);

void mp_set_one(mp_int *a);
void mp_set_sint(mp_int *a, long value);
void mp_set_uint(mp_int *a, unsigned long value);
int  mp_set_str(mp_int *a, const char *str, int base);

int mp_set_uchar(mp_int *a, const unsigned char *buf, int len);
int mp_to_uchar(const mp_int *a, unsigned char *buf, int len);

int mp_nr_bits(const mp_int *a);

int mp_shr(mp_int *a, unsigned int nr);
int mp_shl(mp_int *a, unsigned int nr);

int mp_add(mp_int *c, const mp_int *a, const mp_int *b);
int mp_sub(mp_int *c, const mp_int *a, const mp_int *b);
int mp_mul(mp_int *c, const mp_int *a, const mp_int *b);
int mp_mul_ndig(mp_int *c, const mp_int *a, const mp_int *b, int ndig);
int mp_mul_dig(mp_int *c, const mp_int *a, _mp_int_t b);
int mp_div(mp_int *q, mp_int *r, const mp_int *y, const mp_int *x);
int mp_sqr(mp_int *c, const mp_int *x);

int mp_gcd(mp_int *c, const mp_int *a, const mp_int *b);

int mp_random(mp_int *a, int len, int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx);

int mp_primality_miller_rabin(const mp_int *a, int r, int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx);

int mp_reduce_barrett_setup(mp_int *mu, const mp_int *b);
int mp_reduce_barrett(mp_int *c, const mp_int *a, const mp_int *b, const mp_int *mu);

int mp_mod_inv(mp_int *c, const mp_int *a, const mp_int *b);
int mp_mod_exp(mp_int *res, const mp_int *a, const mp_int *y, const mp_int *b);

int mp_cmp(const mp_int *a, const mp_int *b);
int mp_abs_cmp(const mp_int *a, const mp_int *b);

int mp_copy(mp_int *dst, const mp_int *src);
int mp_swap(mp_int *a, mp_int *b);

#ifdef __cplusplus
}
#endif

#endif

