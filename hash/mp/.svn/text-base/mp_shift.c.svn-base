#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

extern void mp_canonicalize(mp_int *a);

int
mp_shr(mp_int *a, unsigned int nr)
{
	_mp_int_t *dst, *src;
	unsigned int nbits, ndigs;
	int i, n;

	if (nr == 0 || mp_iszero(a))
		return MP_OK;

	ndigs = nr / MP_INT_BITS;
	nbits = nr % MP_INT_BITS;

	n = a->top + 1 - ndigs;
	dst = a->dig;
	src = a->dig + ndigs;

	if (nbits > 0) {
		_mp_int_t mask, shift;

		mask = (~(_mp_int_t)0 & MP_INT_MASK) >> (MP_INT_BITS - nbits);
		shift = MP_INT_BITS - nbits;

		for (i = 1; i < n; i++) {
			*dst = *src >> nbits;
			*dst |= (*(src+1) & mask) << shift;
			++dst; ++src;
		}

		*dst = *src >> nbits;

	} else {
		for (i = 0; i < n; i++)
			*dst++ = *src++;
	}

	for (i = a->top; i > (a->top - ndigs); i--)
		a->dig[i] = 0;

	a->top -= ndigs;

	mp_canonicalize(a);

	return MP_OK;
}

int
mp_shl(mp_int *a, unsigned int nr)
{
	_mp_int_t *dst, *src;
	unsigned int ensure;
	unsigned int nbits, ndigs;
	int i, n, rc;

	if (nr == 0 || mp_iszero(a))
		return MP_OK;

	ndigs = nr / MP_INT_BITS;
	nbits = nr % MP_INT_BITS;
	ensure = a->top + 1 + ndigs;
	ensure += nbits > 0 ? 1 : 0;

	if ((rc = mp_ensure(a, ensure)) != MP_OK)
		return rc;

	n = a->top + 1;
	dst = a->dig + a->top + ndigs;
	src = a->dig + a->top;

	if (nbits > 0) {
		_mp_int_t mask, shift;

		shift = MP_INT_BITS - nbits;
		mask = (~(_mp_int_t)0 << shift) & MP_INT_MASK;

		for (i = 0; i < n; i++) {
			*(dst+1) |= (*src & mask) >> shift;
			*dst = (*src << nbits) & MP_INT_MASK;
			--dst; --src;
		}

	} else {
		for (i = 0; i < n; i++)
			*dst-- = *src--;
	}

	for (i = 0; i < ndigs; i++)
		a->dig[i] = 0;

	a->top += ndigs + (nbits ? 1 : 0);

	mp_canonicalize(a);

	return MP_OK;
}

