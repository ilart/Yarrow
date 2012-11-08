#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

int
mp_mod_inv(mp_int *c, const mp_int *a, const mp_int *b)
{
	mp_int x1, x2, y1, y2;
	mp_int x, y, u, v;
	int rc;

	/* Modulo can't be negative. */
	if (b->sign == MP_SIGN_NEG)
		return MP_ERR;

	/* 0 < a < b */
	if (mp_iszero(a) || mp_iszero(b))
		return MP_ERR;

	if (mp_abs_cmp(a, b) == MP_CMP_GT)
		return MP_ERR;

	/* Both a and b can't be even because then gcd(a, b) != 1. */
	if (mp_iseven(a) && mp_iseven(b))
		return MP_ERR;
	
	if ((rc = mp_initv(&x1, &x2, &y1, &y2, &u, &v, NULL)) != MP_OK)
		return rc;

	x.sign = MP_SIGN_POS;
	x.dig = a->dig;
	x.top = a->top;
	x.alloc = 0;

	y.sign = MP_SIGN_POS;
	y.dig = b->dig;
	y.top = b->top;
	y.alloc = 0;

	rc = mp_copy(&u, &x);
	if (rc != MP_OK)
		goto err;

	rc = mp_copy(&v, &y);
	if (rc != MP_OK)
		goto err;

	mp_set_one(&x1);
	mp_set_one(&y2);

	do { 
		while (mp_iseven(&u)) {
			/* u = u / 2 */
			rc = mp_shr(&u, 1);
			if (rc != MP_OK)
				goto err;

			if (mp_isodd(&x1) || mp_isodd(&y1)) {
				/* x1 = x1 + y, y1 = y1 - x */
				rc = mp_add(&x1, &x1, &y);
				if (rc != MP_OK)
					goto err;
				rc = mp_sub(&y1, &y1, &x);
				if (rc != MP_OK)
					goto err;
			}

			/* x1 = x1 / 2, y1 = y1 / 2 */
			rc = mp_shr(&x1, 1);
			if (rc != MP_OK)
				goto err;

			rc = mp_shr(&y1, 1);
			if (rc != MP_OK)
				goto err;
		}

		while (mp_iseven(&v)) {
			/* v = v / 2 */
			rc = mp_shr(&v, 1);
			if (rc != MP_OK)
				goto err;

			if (mp_isodd(&x2) || mp_isodd(&y2)) {
				/* x2 = x2 + y, y2 = y2 - x */
				rc = mp_add(&x2, &x2, &y);
				if (rc != MP_OK)
					goto err;
				rc = mp_sub(&y2, &y2, &x);
				if (rc != MP_OK)
					goto err;
			}

			/* x2 = x2 / 2 */
			rc = mp_shr(&x2, 1);
			if (rc != MP_OK)
				goto err;

			/* y2 = y2 / 2 */
			rc = mp_shr(&y2, 1);
			if (rc != MP_OK)
				goto err;
		}

		if (mp_cmp(&u, &v) != MP_CMP_LT) {
			/* u = u - v, x1 = x1 - x2, y1 = y1 - y2 */
			rc = mp_sub(&u, &u, &v);
			if (rc != MP_OK)
				goto err;
			rc = mp_sub(&x1, &x1, &x2);
			if (rc != MP_OK)
				goto err;
			rc = mp_sub(&y1, &y1, &y2);
			if (rc != MP_OK)
				goto err;
		} else {
			/* v = v - u, x2 = x2 - x1, y2 = y2 - y1 */
			rc = mp_sub(&v, &v, &u);
			if (rc != MP_OK)
				goto err;
			rc = mp_sub(&x2, &x2, &x1);
			if (rc != MP_OK)
				goto err;
			rc = mp_sub(&y2, &y2, &y1);
			if (rc != MP_OK)
				goto err;
		}

	} while (!mp_iszero(&u) && !mp_iszero(&v));

	if (mp_iszero(&v)) {
		
		if (!mp_isone(&u))
			return MP_ERR;

		rc = mp_copy(c, &x1);
		if (rc != MP_OK)
			goto err;
	} else {
		
		if (!mp_isone(&v))
			return MP_ERR;
		
		rc = mp_copy(c, &x2);
		if (rc != MP_OK)
			goto err;
	}

	/* Result is congruent modulo b. */
	while (mp_cmp(c, b) == MP_CMP_GT) {
		if ((rc = mp_sub(c, c, b)) != MP_OK)
			goto err;
	}

	while (c->sign == MP_SIGN_NEG) {
		if ((rc = mp_add(c, c, b)) != MP_OK)
			goto err;
	}

	rc = MP_OK;
err:
	mp_clearv(&x1, &x2, &y1, &y2, &u, &v, NULL);
	return rc;
}

