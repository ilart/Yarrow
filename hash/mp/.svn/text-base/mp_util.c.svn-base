#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

int
mp_iszero(const mp_int *a)
{
	return (a->top < 0 ? 1 : 0);
}

int
mp_isone(const mp_int *a)
{
	return (a->top == 0 && a->dig[0] == 1);
}

int
mp_isneg(const mp_int *a)
{
	return (a->sign == MP_SIGN_NEG);
}

/* memset() for MP integer. */
void
mp_zero(mp_int *a)
{
	int i, top;

	top = a->top;

	for (i = 0; i <= top; i++)
		a->dig[i] = 0;

	a->sign = MP_SIGN_POS;
	a->top = -1;
}

/* Removes excessive zeros and fixes the sign if needed. */
void
mp_canonicalize(mp_int *a)
{
	int top;

	top = a->top;

	while (top >= 0 && a->dig[top] == 0)
		--top;

	if (top < 0)
		a->sign = MP_SIGN_POS;

	a->top = top;
}

/* Swaps two MP integers. */
int
mp_swap(mp_int *a, mp_int *b)
{
	mp_int tmp;

	if (a == b)
		return MP_OK;

	memcpy(&tmp, a, sizeof(tmp));
	memcpy(a, b, sizeof(*a));
	memcpy(b, &tmp, sizeof(*b));

	return MP_OK;
}

int
mp_nr_bits(const mp_int *a)
{
	_mp_int_t dig;
	int res, cnt;

	if (mp_iszero(a))
		return 0;

	res = a->top * MP_INT_BITS;
	dig = a->dig[a->top];

	cnt = 0;
	while (dig > 0) {
		dig >>= 1;
		++cnt;
	}

	res += cnt;

	return res;
}

void
mp_dbg(const mp_int *a, FILE *fp)
{
	_mp_int_t *ap;
	int i, top;

	fprintf(fp, "%p: top=%04d alloc=%04d: ", a, a->top, a->alloc);

	if (mp_iszero(a)) {
		fprintf(fp, "0\n");
		return;
	}

	top = a->top;
	ap = a->dig;

	if (a->sign == MP_SIGN_NEG)
		fprintf(fp, "-");
	else
		fprintf(fp, " ");

	for (i = top; i >= 0; i--)
		fprintf(fp, "%07X", ap[i]);
	fprintf(fp, "\n");
}

