#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern int _mp_add(mp_int *c, const mp_int *a, const mp_int *b);

extern void mp_canonicalize(mp_int *a);

/* Subtracts c = |a| - |b|. Algorithm requires that |a| > |b|. */
int
_mp_sub(mp_int *c, const mp_int *a, const mp_int *b)
{
	_mp_int_t *ap, *bp, *cp, cr;
	int btop, ctop, oldtop;
	int i, rc;

	if ((rc = mp_ensure(c, a->top+1)) != MP_OK)
		return rc;

	btop = b->top;
	ctop = a->top;
	oldtop = c->top;
	ap = a->dig;
	bp = b->dig;
	cp = c->dig;
	cr = 0;

	for (i = 0; i <= btop; i++) {
		*cp = (*ap++) - (*bp++) - cr;
		cr = *cp >> (MP_INT_BITS_ALL-1);
		*cp++ &= MP_INT_MASK;
	}

	for (i = btop+1; i <= ctop; i++) {
		*cp = (*ap++) - cr;
		cr = *cp >> (MP_INT_BITS_ALL-1);
		*cp++ &= MP_INT_MASK;
	}

	/* Zero unused digits in the result. */
	for (i = ctop+1; i <= oldtop; i++)
		*cp++ = 0;

	c->top = ctop;

	mp_canonicalize(c);

	return MP_OK;
}

int
mp_sub(mp_int *c, const mp_int *a, const mp_int *b)
{
	int rc;

	if (a->sign == b->sign) {
		switch (mp_abs_cmp(a, b)) {
		case MP_CMP_GT:
			/* |a| > |b|, c = sign(a)(|a| - |b|) */
			if ((rc = _mp_sub(c, a, b)) != MP_OK)
				return rc;
			c->sign = a->sign;
			break;
		case MP_CMP_LT:
			/* |a| < |b|, c = inv(sign(b))(|b| - |a|) */
			if ((rc = _mp_sub(c, b, a)) != MP_OK)
				return rc;
			c->sign = (b->sign == MP_SIGN_POS ? MP_SIGN_NEG : MP_SIGN_POS);
			break;
		case MP_CMP_EQ:
			/* |a| = |b|, c = 0 */
			mp_zero(c);
			break;
		}
	} else {
		/* c = sign(a)(|a| + |b|). */
		if ((rc = _mp_add(c, a, b)) != MP_OK)
			return rc;
		c->sign = a->sign;
	}

	return MP_OK;
}

