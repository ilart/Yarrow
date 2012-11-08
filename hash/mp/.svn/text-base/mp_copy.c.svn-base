#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

int
mp_copy(mp_int *dst, const mp_int *src)
{	
	_mp_int_t *dp, *sp;
	int src_top, dst_top;
	int i, rc;

	if (dst == src)
		return MP_OK;

	if (mp_iszero(src)) {
		mp_zero(dst);
		return MP_OK;
	}

	if ((rc = mp_ensure(dst, src->top+1)) != MP_OK)
		return rc;

	src_top = src->top;
	dst_top = dst->top;
	dp = dst->dig;
	sp = src->dig;

	for (i = 0; i <= src_top; i++)
		*dp++ = *sp++;

	for (; i <= dst_top; i++)
		*dp++ = 0;

	dst->top = src_top;
	dst->sign = src->sign;

	return MP_OK;
}

