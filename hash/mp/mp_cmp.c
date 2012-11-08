#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

/* Compares absolute values |a| and |b|. */
int
_mp_abs_cmp(const mp_int *a, const mp_int *b)
{
	_mp_int_t *ap, *bp;
	int i;

	if (a->top > b->top)
		return MP_CMP_GT;
	else if (a->top < b->top)
		return MP_CMP_LT;

	/* a and b have equal no of digits */
	ap = a->dig + a->top;
	bp = b->dig + b->top;

	for (i = a->top; i >= 0; i--) {
		if (*ap != *bp) {
			if (*ap > *bp)
				return MP_CMP_GT;
			else if (*ap < *bp)
				return MP_CMP_LT;
		}
		--ap; --bp;
	}

	return MP_CMP_EQ;
}

int
mp_abs_cmp(const mp_int *a, const mp_int *b)
{	
	if (a == b || (mp_iszero(a) && mp_iszero(b)))
		return MP_CMP_EQ;

	return _mp_abs_cmp(a, b);
}

int
mp_cmp(const mp_int *a, const mp_int *b)
{
	int res;

	if (a == b || (mp_iszero(a) && mp_iszero(b)))
		return MP_CMP_EQ;

	if (a->sign != b->sign)
		return a->sign == MP_SIGN_POS ? MP_CMP_GT : MP_CMP_LT;
 
	if (a->sign == MP_SIGN_NEG)
		res = _mp_abs_cmp(b, a);
	else
		res = _mp_abs_cmp(a, b);

	return res;
}

