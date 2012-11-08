#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "mp.h"
#include "mp_common.h"

void
mp_set_sint(mp_int *a, long val)
{
	int i, oldtop;
	_mp_int_t *dp;

	oldtop = a->top;

	a->top = 0;
	a->sign = (val >= 0 ? MP_SIGN_POS : MP_SIGN_NEG);

	if (val >= 0)
		a->dig[0] = val & MP_INT_MASK;
	else
		a->dig[0] = -val & MP_INT_MASK;

	dp = a->dig + 1;

	for (i = 1; i <= oldtop; i++)
		*dp++ = 0;
}

void
mp_set_uint(mp_int *a, unsigned long val)
{
	int i, oldtop;
	_mp_int_t *dp;

	oldtop = a->top;

	a->top = 0;
	a->sign = MP_SIGN_POS;
	a->dig[0] = val & MP_INT_MASK;

	dp = a->dig + 1;

	for (i = 1; i <= oldtop; i++)
		*dp++ = 0;
}

int
mp_set(mp_int *a, unsigned long *val, unsigned int nval, int sign)
{
	_mp_int_t *ap;
	int i, rc, top;

	if ((rc = mp_ensure(a, nval)) != MP_OK)
		return rc;

	ap = a->dig;
	top = a->top;

	/* Copy digits to MP integer. */
	for (i = 0; i < nval; i++)
		*ap++ = *val++ & MP_INT_MASK;

	/* All digits beyond top (if any) are zeroed. */
	if (top >= nval) {
		for (i = nval; i <= top; i++)
			*ap++ = 0;
	}

	a->top = nval-1;
	a->sign = sign;

	return MP_OK;
}

void
mp_set_one(mp_int *a)
{
	mp_set_uint(a, 1);
}

int
mp_set_str(mp_int *a, const char *str, int base)
{
	mp_int tmp;
	int i, n, rc;
	int dig;
	char c;

	if (base < 2 || base > 36)
		return MP_ERR;

	rc = mp_init(&tmp);
	if (rc != MP_OK)
		return rc;

	mp_zero(a);

	n = strlen(str);

	for (i = 0; i < n; i++) {

		c = *str++;

		if (c >= '0' && c <= '9')
			dig = c - '0';
		else
			dig = toupper(c) - 'A' + 10;

		if (dig < 0 || dig >= base) {
			rc = MP_ERR;
			goto err;
		}

		rc = mp_mul_dig(a, a, base);
		if (rc != MP_OK)
			goto err;

		mp_set_uint(&tmp, dig);
		
		rc = mp_add(a, a, &tmp);
		if (rc != MP_OK)
			goto err;
	}
	
	rc = MP_OK;
err:
	mp_clear(&tmp);
	return rc;
}

