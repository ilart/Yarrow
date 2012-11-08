#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern void mp_canonicalize(mp_int *a);

int
_mp_sqr_karatsuba(mp_int *c, const mp_int *x)
{
	mp_int a2, b2, tmp;
	mp_int a, b;
	unsigned int n;
	int top, rc;

	top = x->top;

	if ((rc = mp_initv(&a2, &b2, &tmp, NULL)) != MP_OK)
		return rc;

	/* Select half digits of the smallest number. */
	n = (top + 1) >> 1;

	/* Set up intermediate values used to calculate partial multiplications. */
	b.dig = x->dig;
	b.sign = MP_SIGN_POS;
	b.top = n-1;
	b.alloc = 0;

	a.dig = x->dig + n;
	a.sign = MP_SIGN_POS;
	a.top = top - n;
	a.alloc = 0;

	/* a^2 and b^2 */
	rc = mp_sqr(&a2, &a);
	if (rc != MP_OK)
		goto err;

	rc = mp_sqr(&b2, &b);
	if (rc != MP_OK)
		goto err;

	/* tmp = (a+b)^2 - a^2 - b^2 */
	rc = mp_add(&tmp, &a, &b);
	if (rc != MP_OK)
		goto err;

	rc = mp_sqr(&tmp, &tmp);
	if (rc != MP_OK)
		goto err;
	
	rc = mp_sub(&tmp, &tmp, &a2);
	if (rc != MP_OK)
		goto err;

	rc = mp_sub(&tmp, &tmp, &b2);
	if (rc != MP_OK)
		goto err;

	/* c = a^2*2^2n + ((a + b)^2 - (a^2 + b^2))*2^n + b^2 */
	rc = mp_shl(&a2, (n*MP_INT_BITS));
	if (rc != MP_OK)
		goto err;

	rc = mp_add(c, &a2, &tmp);
	if (rc != MP_OK)
		goto err;

	rc = mp_shl(c, (n*MP_INT_BITS));
	if (rc != MP_OK)
		goto err;

	rc = mp_add(c, c, &b2);
	if (rc != MP_OK)
		goto err;

	rc = MP_OK;
err:
	mp_clearv(&a2, &b2, &tmp, NULL);
	return rc;
}

int
_mp_sqr_school(mp_int *c, const mp_int *a)
{
	mp_int tmpint;
	_mp_long_t w;
	_mp_int_t *ap, *tmp;
	_mp_int_t dig;
	int i, j, n, rc;
	int top;

	top = a->top;
	n = (top + 1) << 1;

	if ((rc = mp_init(&tmpint)) != MP_OK)
		return rc;

	--n;
	top = a->top;

	for (i = 0; i <= top; i++) {

		w = 0;
		ap = a->dig + i;
		dig = *ap++;

		/* Add square first. */
		tmp = tmpint.dig + (i << 1);
		w = (((_mp_long_t)dig) * ((_mp_long_t)dig)) + (_mp_long_t)*tmp;
		*tmp++ = w & MP_INT_MASK;
		w >>= MP_INT_BITS;

		/* Next products have a factor of two. */
		for (j = i; j < top; j++) {
			w += (((_mp_long_t)*ap++ * (_mp_long_t)dig) << 1) + (_mp_long_t)*tmp;
			*tmp++ = w & MP_INT_MASK;
			w >>= MP_INT_BITS;
		}

		/* Final carry. */
		*tmp = w;
	}

	tmpint.top = n;

	if ((rc = mp_copy(c, &tmpint)) != MP_OK)
		goto err_copy;

	mp_canonicalize(c);
	rc = MP_OK;

err_copy:
	mp_clear(&tmpint);
	return rc;
}

int
_mp_sqr_comba(mp_int *c, const mp_int *a)
{
	_mp_int_t tmp[MP_COMBA_STACK], *cp;
	_mp_long_t w;
	int i, n;
	int rc, top, ctop;

	top = a->top;
	n = (top + 1) << 1;

	if ((rc = mp_ensure(c, n)) != MP_OK)
		return rc;

	/* Turn n into maximum number of iterations. */
	--n;

	/* Reset accumulator. */
	w = 0;

	for (i = 0; i < n; i++) {
		int begin, end;
		_mp_int_t *p, *p2;

		tmp[i] = 0;
		begin = (i <= top) ? 0 : i - top;
		end = (i <= top) ? i : top;

		p = a->dig + begin;
		p2 = a->dig + end;

		/* Add two multiples of digits to accumulator. */
		while (p < p2)
			w += ((_mp_long_t)(*p++) * (_mp_long_t)(*p2--)) << 1;

		/* When i is even, add square. */
		if ((i & 0x01) == 0)
			w += (_mp_long_t)(*p) * (_mp_long_t)(*p);

		/* Store result. */
		tmp[i] = w & (_mp_long_t)MP_INT_MASK;

		/* Save carry for the next iteration. */
		w >>= MP_INT_BITS;
	}

	/* Store final carry or 0 if none. */
	tmp[i] = w;

	cp = c->dig;
	ctop = c->top;
	c->top = n;

	/* Copy result. */
	for (i = 0; i <= n; i++)
		*cp++ = tmp[i];

	/* Zero unused digits in c. */
	for (; i <= ctop; i++)
		*cp++ = 0;

	mp_canonicalize(c);

	return MP_OK;
}

int
mp_sqr(mp_int *c, const mp_int *x)
{
	int rc;

	if ((x->top+1) >= MP_KARATSUBA_CUTOFF)
		rc = _mp_sqr_karatsuba(c, x);
	else if (((x->top+1) << 1) <= MP_COMBA_STACK &&
		  x->top+1 <= MP_COMBA_DEPTH)
		rc = _mp_sqr_comba(c, x);
	else
		rc = _mp_sqr_school(c, x);

	/* squaring always gives positive sign */
	c->sign = MP_SIGN_POS;
	
	return rc;
}

