#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern int _mp_sub(mp_int *c, const mp_int *a, const mp_int *b);

extern int mp_canonicalize(mp_int *a);

/* Adds c = |a| + |b|, c can point to a or b. */
int
_mp_add(mp_int *c, const mp_int *a, const mp_int *b)
{
	_mp_int_t *ap, *bp, *cp, cr;
	int btop, ctop, i, oldtop, rc;

	if (a->top < b->top) {
		const mp_int *tmp;
		tmp = a;
		a = b;
		b = tmp;
	}

	/* Ensure we have space for an additional digit. */
	if ((rc = mp_ensure(c, a->top+2)) != MP_OK)
		return rc;

	ap = a->dig;
	bp = b->dig;
	cp = c->dig;
	btop = b->top;
	ctop = a->top + 1;
	oldtop = c->top;

	cr = 0;

	for (i = 0; i <= btop; i++) {
		*cp = (*ap++) + (*bp++) + cr;
		cr = *cp >> MP_INT_BITS;
		*cp++ &= MP_INT_MASK;
	}

	for (i = btop+1; i < ctop; i++) {
		*cp = (*ap++) + cr;
		cr = *cp >> MP_INT_BITS;
		*cp++ &= MP_INT_MASK;
	}

	*cp++ = cr;

	/* Zero unused digits in the result. */
	for (i = ctop+1; i <= oldtop; i++)
		*cp++ = 0;

	c->top = ctop;

	mp_canonicalize(c);

	return MP_OK;
}

int
mp_add(mp_int *c, const mp_int *a, const mp_int *b)
{
	int rc;

	if (a->sign == b->sign) {
		/* Do addition c = |a| + |b|. */
		if ((rc = _mp_add(c, a, b)) != MP_OK)
			return rc;
		/* Result sign is the sign of a or b. */
		c->sign = a->sign;
	} else {
		if (mp_abs_cmp(a, b) == MP_CMP_GT) {
			if ((rc = _mp_sub(c, a, b)) != MP_OK)
				return rc;
			c->sign = a->sign;
		} else {
			if ((rc = _mp_sub(c, b, a)) != MP_OK)
				return rc;
			c->sign = b->sign;
		}
	}

	return MP_OK;
}

