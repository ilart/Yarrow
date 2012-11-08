#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "mp.h"
#include "mp_common.h"

int
mp_primality_miller_rabin(const mp_int *m, int r,
			  int (*rnd)(void *buf, size_t size, void *rndctx),
			  void *rndctx)
{
	mp_int m_minus_one, one;
	mp_int m_mod, a, t, x, mu;
	int i, rc, s, n;

	if (rnd == NULL || r == 0 || mp_iszero(m))
		return MP_ERR;

	rc = mp_initv(&m_minus_one, &one, &a, &t, &x, &mu, NULL);
	if (rc != MP_OK)
		return rc;

	/* m_mod = |m| */
	m_mod.dig = m->dig;
	m_mod.top = m->top;
	m_mod.sign = MP_SIGN_POS;
	m_mod.alloc = 0;

	/* one = 1, m_minus_one = |m| - 1 */
	mp_set_one(&one);

	rc = mp_sub(&m_minus_one, &m_mod, &one);
	if (rc != MP_OK)
		goto out;

	/* Prepare Barrett reduction precalculated constant. */
	rc = mp_reduce_barrett_setup(&mu, &m_mod);
	if (rc != MP_OK)
		goto out;

	/* Determine power of two used to construct |m|-1 = 2^s * t. */
	s = 0;
	n = m_minus_one.top + 1;

	for (i = 0; i < n; i++) {
		_mp_int_t dig;
		int cnt;

		dig = m_minus_one.dig[i];

		for (cnt = 0; cnt < MP_INT_BITS; cnt++) {
			if (dig & 0x1)
				goto brk_loop;
			dig >>= 1;
			++s;
		}
	}

brk_loop:

	/* The following condition is a paranoidal check. */
	if (i >= n) {
		rc = MP_ERR;
		goto out;
	}

	/* m_minus_one = 2^s * t */
	rc = mp_copy(&t, &m_minus_one);
	if (rc != MP_OK)
		goto out;

	if (s > 0) {
		rc = mp_shr(&t, s);
		if (rc != MP_OK)
			goto out;
	}

	/* Number of random bytes one digit less then m. */
	n = (m->top * MP_INT_BITS) / CHAR_BIT;

	for (i = 0; i < r; i++) {
		int j;

		rc = mp_random(&a, n, rnd, rndctx);
		if (rc != MP_OK)
			goto out;

		rc = mp_mod_exp(&x, &a, &t, &m_mod);
		if (rc != MP_OK)
			goto out;

		if (mp_cmp(&x, &one) == MP_CMP_EQ)
			continue;

		if (mp_cmp(&x, &m_minus_one) == MP_CMP_EQ)
			continue;

		for (j = 1; j < s; j++) {
			
			rc = mp_sqr(&x, &x);
			if (rc != MP_OK)
				goto out;

			rc = mp_reduce_barrett(&x, &x, &m_mod, &mu);
			if (rc != MP_OK)
				goto out;

			if (mp_isone(&x)) {
				rc = MP_COMPOSITE;
				goto out;
			}

			if (mp_cmp(&x, &m_minus_one) == MP_CMP_EQ)
				break;
		}

		if (j >= s) {
			rc = MP_COMPOSITE;
			goto out;
		}
	}

	rc = MP_OK;
out:
	mp_clearv(&m_minus_one, &one, &a, &t, &x, &mu, NULL);
	return rc;
}

