#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

int
mp_gcd(mp_int *c, const mp_int *a, const mp_int *b)
{
	mp_int x, y, u, v;
	int rc, k;
	
	if ((rc = mp_initv(&u, &v, NULL)) != MP_OK)
		return rc;

	x.dig = a->dig;
	x.alloc = a->alloc;
	x.top = a->top;
	x.sign = MP_SIGN_POS;

	y.dig = b->dig;
	y.alloc = b->alloc;
	y.top = b->top;
	y.sign = MP_SIGN_POS;

	rc = mp_copy(&u, &x);
	if (rc != MP_OK)
		goto err;

	rc = mp_copy(&v, &y);
	if (rc != MP_OK)
		goto err;

	k = 0;
	while (mp_iseven(&v) && mp_iseven(&u)) {
		rc = mp_shr(&u, 1);
		if (rc != MP_OK)
			goto err;
		rc = mp_shr(&v, 1);
		if (rc != MP_OK)
			goto err;
		++k;
	}

	do {
		/* Reduce u by factor of two. */
		while (mp_iseven(&u)) {
			rc = mp_shr(&u, 1);
			if (rc != MP_OK)
				goto err;
		}

		/* Reduce v by factor of two. */
		while (mp_iseven(&v)) {
			rc = mp_shr(&v, 1);
			if (rc != MP_OK)
				goto err;
		}

		/* Reduce greatest of u or v. */
		if (mp_cmp(&u, &v) != MP_CMP_LT) {
			/* u = (u - v) / 2 */
			rc = mp_sub(&u, &u, &v);
			if (rc != MP_OK)
				goto err;
			rc = mp_shr(&u, 1);
			if (rc != MP_OK)
				goto err;
		} else {
			/* v = (v - u) / 2 */
			rc = mp_sub(&v, &v, &u);
			if (rc != MP_OK)
				goto err;
			rc = mp_shr(&v, 1);
			if (rc != MP_OK)
				goto err;
		}

	} while (!mp_iszero(&u) && !mp_iszero(&v));

	if (mp_iszero(&u)) {
		rc = mp_copy(c, &v);
		if (rc != MP_OK)
			goto err;
	} else {
		rc = mp_copy(c, &u);
		if (rc != MP_OK)
			goto err;
	}

	if (k > 0) {
		rc = mp_shl(c, k);
		if (rc != MP_OK)
			goto err;
	}

	rc = MP_OK;
err:
	mp_clearv(&u, &v, NULL);
	return rc;
}

