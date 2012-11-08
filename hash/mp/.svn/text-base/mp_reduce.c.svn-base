#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern int _mp_mul_comba_upper(mp_int *c, const mp_int *a, const mp_int *b, int digit);

int
mp_reduce_barrett_setup(mp_int *mu, const mp_int *b)
{
	mp_int q;
	int m2, rc;

	/* 2m */
	m2 = ((b->top+1) << 1);

	if ((rc = mp_init(&q)) != MP_OK)
		return rc;

	mp_set_one(&q);
	
	rc = mp_shl(&q, m2*MP_INT_BITS);
	if (rc != MP_OK)
		goto err;

	rc = mp_div(mu, NULL, &q, b);
	if (rc != MP_OK)
		goto err;

	rc = MP_OK;
err:
	mp_clear(&q);
	return rc;
}

int
mp_reduce_barrett(mp_int *c, const mp_int *a, const mp_int *b, const mp_int *mu)
{
	mp_int q, amod;
	int m, rc;

	m = b->top + 1;

	if (mp_abs_cmp(a, b) == MP_CMP_LT)
		return MP_OK;

	if ((rc = mp_initv(&q, NULL)) != MP_OK)
		return rc;

	rc = mp_copy(&q, a);
	if (rc != MP_OK)
		goto err;

	rc = mp_shr(&q, (m-1)*MP_INT_BITS);
	if (rc != MP_OK)
		goto err;

	if (MIN(q.top+1, mu->top+1) <= MP_COMBA_DEPTH &&
	    (q.top+1)+(mu->top+1) <= MP_COMBA_STACK) {
		if ((rc = _mp_mul_comba_upper(&q, &q, mu, m-1)) != MP_OK)
			goto err;
	} else {
		if ((rc = mp_mul(&q, &q, mu)) != MP_OK)
			goto err;
	}

	rc = mp_shr(&q, (m+1)*MP_INT_BITS);
	if (rc != MP_OK)
		goto err;

	/* Reduce a by mod b^m+1, i.e. use only m+1 digits. */
	amod.alloc = 0;
	amod.dig = a->dig;
	amod.sign = MP_SIGN_POS;
	/* a mod b^m+1 */
	amod.top = m;

	rc = mp_mul_ndig(&q, &q, b, m+1);
	if (rc != MP_OK)
		goto err;

	rc = mp_sub(c, &amod, &q);
	if (rc != MP_OK)
		goto err;

	/* Add BASE^m+1 if result is negative. */
	if (c->sign == MP_SIGN_NEG) {

		mp_set_one(&q);
		
		rc = mp_shl(&q, (m+1)*MP_INT_BITS);
		if (rc != MP_OK)
			goto err;
		
		rc = mp_add(c, c, &q);
		if (rc != MP_OK)
			goto err;
	}

	/* Subtract b from a. This step performs two times at maximum. */
	while (mp_cmp(c, b) != MP_CMP_LT) {
		rc = mp_sub(c, c, b);
		if (rc != MP_OK)
			goto err;
	}

	rc = MP_OK;
err:
	mp_clearv(&q, NULL);
	return rc;
}

