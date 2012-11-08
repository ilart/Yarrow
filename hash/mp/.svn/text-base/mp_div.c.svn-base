#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern void mp_canonicalize(mp_int *a);

int
mp_div(mp_int *q, mp_int *r, const mp_int *y, const mp_int *x)
{
	mp_int u, v, tmp;
	_mp_int_t dig;
	int norm, cnt, rc;
	int i, n, t, sign;

	if (mp_iszero(x))
		return MP_ERR;

	if (mp_abs_cmp(x, y) == MP_CMP_GT) {
		if (r != NULL) {
			if ((rc = mp_copy(r, x)) != MP_OK)
				return rc;
		}
		mp_zero(q);
		return MP_OK;
	}

	if ((rc = mp_initv(&u, &v, &tmp, NULL)) != MP_OK)
		return rc;

	if ((rc = mp_copy(&u, y)) != MP_OK)
		goto err;

	if ((rc = mp_copy(&v, x)) != MP_OK)
		goto err;

	/* Guess about the result sign. */
	sign = (y->sign == x->sign) ? MP_SIGN_POS: MP_SIGN_NEG;

	/* Reserve memory in quotient and remainder. */
	if ((rc = mp_ensure(q, y->top - x->top + 1)) != MP_OK)
		goto err;

	if (r != NULL) {
		if ((rc = mp_ensure(r, x->top + 1)) != MP_OK)
			goto err;
	}

	/* Count bits of the topmost digit of divider. */
	dig = x->dig[x->top];
	cnt = 0;
	while (dig > 0) {
		dig >>= 1;
		++cnt;
	}

	/* Normalize divider and dividend. */
	if (cnt < MP_INT_BITS) {
		norm = (MP_INT_BITS) - cnt;
		if ((rc = mp_shl(&u, norm)) != MP_OK)
			goto err;
		if ((rc = mp_shl(&v, norm)) != MP_OK)
			goto err;
	} else {
		norm = 0;
	}

	/* Setup quotient properties known in advance. */
	mp_zero(q);
	q->top = y->top - x->top;
	q->sign = sign;

	for (;;) {
		n = u.top;
		t = v.top;
		if (n < t)
			break;
		cnt = (n - t) * MP_INT_BITS;
		mp_shl(&v, cnt);
		if (mp_abs_cmp(&u, &v) != MP_CMP_LT) {
			do {
				++q->dig[n-t];
				if ((rc = mp_sub(&u, &u, &v)) != MP_OK)
					goto err;
			} while (mp_abs_cmp(&u, &v) != MP_CMP_LT);
			mp_shr(&v, cnt);
		} else {
			mp_shr(&v, cnt);
			break;
		}
	}

	for (i = n; i >= t+1; i--) {
		_mp_int_t tmpint[3];
		_mp_int_t qcap;
		mp_int tmp2;
		int qpos;

		/* Skip empty dividend digits. */
		if (i > u.top)
			continue;

		/* Precalculate quotient digit position. */
		qpos = i - t - 1;

		/* First approximation to quotient. */
		if (u.dig[i] == v.dig[t]) {
			qcap = MP_INT_BASE-1;
		} else {
			_mp_long_t tmp;
			tmp  = (_mp_long_t) u.dig[i] << MP_INT_BITS;
			tmp |= (_mp_long_t) u.dig[i-1];
			tmp /= (_mp_long_t) v.dig[t];
			if (tmp >= MP_INT_BASE)
				tmp = MP_INT_BASE-1;
			qcap = tmp & MP_INT_MASK;
		}

		++qcap;

		/* 
		 * Refine quotient approximation using 3 digits of dividend and
		 * 2 digits of divisor. This refinement ensures that quotient
		 * will be less then or equal to (q+1).
		 */
		do {
			--qcap;
			tmp.top = 1;
			tmp.sign = MP_SIGN_POS;
			tmp.dig[1] = v.dig[t];
			tmp.dig[0] = t > 0 ? v.dig[t-1] : 0;

			tmp2.top = 2;
			tmp2.dig = tmpint;
			tmp2.sign = MP_SIGN_POS;
			tmpint[2] = u.dig[i];
			tmpint[1] = i > 0 ? u.dig[i-1] : 0;
			tmpint[0] = i > 1 ? u.dig[i-2] : 0;

			if ((rc = mp_mul_dig(&tmp, &tmp, qcap)) != MP_OK)
				goto err;

			++cnt;
		} while (mp_abs_cmp(&tmp, &tmp2) == MP_CMP_GT);
	
		/* u = u - qv*b^{i-t-1} */

		if ((rc = mp_mul_dig(&tmp, &v, qcap)) != MP_OK)
			goto err;

		if ((rc = mp_shl(&tmp, qpos*MP_INT_BITS)) != MP_OK)
			goto err;

		if ((rc = mp_sub(&u, &u, &tmp)) != MP_OK)
			goto err;

		if (u.sign == MP_SIGN_NEG) {
			/* Fix divisor if the quotient approximation was by one bigger. */
			--qcap;
			if ((rc = mp_mul_dig(&tmp, &v, qcap)) != MP_OK)
				goto err;
			if ((rc == mp_shl(&tmp, qpos*MP_INT_BITS)) != MP_OK)
				goto err;	
			if ((rc = mp_add(&u, &u, &tmp)) != MP_OK)
				goto err;
		}

		/* Store quotient digit. */
		q->dig[qpos] = qcap;
	}

	if (r != NULL) {
		mp_copy(r, &u);
		if (norm > 0)
			mp_shr(r, norm);
		r->sign = y->sign;
	}

	mp_canonicalize(q);
	rc = MP_OK;
err:
	mp_clearv(&u, &v, &tmp, NULL);
	return rc;
}

