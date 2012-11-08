#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

#define MP_MODEXP_STACK	128

int
mp_mod_exp(mp_int *res, const mp_int *a, const mp_int *y, const mp_int *b)
{

	mp_int w[MP_MODEXP_STACK];
	mp_int e, c, mu;
	_mp_int_t *dp, buffer;
	int i, k, nbits, rc;
	int do_single;
	unsigned int mask, x, n, tmp, cnt;

	if ((rc = mp_initv(&e, &c, &mu, NULL)) != MP_OK)
		return rc;

	n = mp_nr_bits(y);

	if (n <= 7)
		k = 2;
	else if (n <= 36)
		k = 3;
	else if (n <= 140)
		k = 4;
	else if (n <= 450)
		k = 5;
	else if (n <= 1303)
		k = 6;
	else if (n <= 3529)
		k = 7;
	else
		k = 8;

	cnt = 0;

	for (i = 0; i < 1 << (k-1); i++) {
		rc = mp_init(&w[i]);
		if (rc != MP_OK) {
			for (i = 0; i < cnt; i++)
				mp_clear(&w[i]);
			return rc;
		}
		++cnt;
	}

	/* e = a */
	rc = mp_copy(&e, a);
	if (rc != MP_OK)
		goto err;

	/* c = 1 */
	mp_set_one(&c);

	/* prepare reduction constant */
	rc = mp_reduce_barrett_setup(&mu, b);
	if (rc != MP_OK)
		goto err;

	/* e = a^{2^(k-1)} */
	for (i = 0; i < k-1; i++) {
		rc = mp_sqr(&e, &e);
		if (rc != MP_OK)
			goto err;
		rc = mp_reduce_barrett(&e, &e, b, &mu);
		if (rc != MP_OK)
			goto err;
	}

	/* Now fill precomputed table. */
	rc = mp_copy(&w[0], &e);
	if (rc != MP_OK)
		goto err;

	for (i = 1; i < 1 << (k-1); i++) {
		/* w[i] = (w[i-1] * a) mod b */
		rc = mp_mul(&w[i], &w[i-1], a);
		if (rc != MP_OK)
			goto err;
		rc = mp_reduce_barrett(&w[i], &w[i], b, &mu);
		if (rc != MP_OK)
			goto err;
	}
	
	buffer = nbits = do_single = cnt = 0;

	/* Count bits of the topmost MP integer digit. */
	dp = y->dig + y->top;
	tmp = *dp;
	for (cnt = 0; tmp > 0; cnt++)
		tmp >>= 1;
	nbits = cnt;
	buffer = *dp--;

	/* Precalculated window mask. */
	mask = (1 << k) - 1;

	while (n > 0) {
		unsigned int left, xmask;

		if (nbits == 0) {
			buffer = *dp--;
			nbits = MP_INT_BITS;
		}

		/* Check most significant bit of the bit buffer. */
		if ((buffer & (1 << (nbits-1))) == 0) {
			/* c = c^2 mod b */
			rc = mp_sqr(&c, &c);
			if (rc != MP_OK)
				goto err;

			rc = mp_reduce_barrett(&c, &c, b, &mu);
			if (rc != MP_OK)
				goto err;

			--nbits;
			--n;
			continue;
		}

		if (nbits >= k) {
			/* We have enough bits in the buffer to fill window. */
			x = (buffer & (mask << (nbits-k))) >> (nbits-k);
			nbits -= k;
			n -= k;
		} else {
			/* Less then k bits left in the buffer. */
			left = k;

			/* Consume remaining bits from the buffer. */
			x = buffer & ((1 << nbits)-1);
			left -= nbits;

			/* 
			 * Fallback to single-bit exponentiation if we can't
			 * get enough bits to form a k-bit window.
			 */
			if (n == nbits) {
				do_single = 1;
				break;
			} else if (n < k) {
				n -= nbits;
				buffer = *dp--;
				x <<= n;
				x |= buffer;
				do_single = 1;
				break;
			}

			buffer = *dp--;
			xmask = (1 << left)-1;
			x <<= left;
			x |= (buffer & (xmask << (MP_INT_BITS - left))) >> (MP_INT_BITS - left);
			nbits = MP_INT_BITS - left;
			n -= k;
		}

		/* c = c^2k mod b  */
		for (i = 0; i < k; i++) {
			rc = mp_sqr(&c, &c);
			if (rc != MP_OK)
				goto err;
			rc = mp_reduce_barrett(&c, &c, b, &mu);
			if (rc != MP_OK)
				goto err;
		}

		/* c = c * a[x] */
		tmp = (1 << (k-1))-1;
		rc = mp_mul(&c, &c, &w[x & tmp]);
		if (rc != MP_OK)
			goto err;

		rc = mp_reduce_barrett(&c, &c, b, &mu);
		if (rc != MP_OK)
			goto err;
	}

	if (do_single) {

		while (n > 0) {
			/* c = c^2 */
			rc = mp_sqr(&c, &c);
			if (rc != MP_OK)
				goto err;
			rc = mp_reduce_barrett(&c, &c, b, &mu);
			if (rc != MP_OK)
				goto err;

			if (x & (1 << (n-1))) {
				/* c = c * a mod b*/
				rc = mp_mul(&c, &c, a);
				if (rc != MP_OK)
					goto err;
				rc = mp_reduce_barrett(&c, &c, b, &mu);
				if (rc != MP_OK)
					goto err;
			}
			--n;
		}
	}

	rc = mp_copy(res, &c);
	if (rc != MP_OK)
		goto err;

	rc = MP_OK;

err:
	for (i = 0; i < (1 << (k-1)); i++)
		mp_clear(&w[i]);

	mp_clearv(&c, &e, &mu, NULL);

	return rc;
}

