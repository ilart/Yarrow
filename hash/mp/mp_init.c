#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "mp.h"
#include "mp_common.h"

int
mp_init(mp_int *p)
{
	unsigned int allocsz;
	int i;

	assert(p != NULL);

	allocsz = MP_ALLOC_DEFAULT + MP_ALLOC_APPEND;

	p->dig = malloc(allocsz * sizeof(_mp_int_t));

	if (p->dig == NULL)
		return MP_NOMEM;

	p->flags = 0;
	p->sign = MP_SIGN_POS;
	p->alloc = allocsz;
	p->top = -1;

	for (i = 0; i < allocsz; i++)
		p->dig[i] = 0;
	
	return MP_OK;
}

int
mp_initv(mp_int *a, ...)
{
	unsigned int allocsz, cnt;
	va_list ap, ap_copy;
	_mp_int_t *dp;
	mp_int *p;

	allocsz = MP_ALLOC_DEFAULT + MP_ALLOC_APPEND;

	cnt = 0;
	p = a;
	va_start(ap, a);
	va_copy(ap_copy, ap);

	while (p != NULL) {
		int i;

		dp = malloc(allocsz * sizeof(_mp_int_t));
		if (dp == NULL)
			goto nomem;
		++cnt;
		p->dig = dp;
		p->flags = 0;
		p->sign = MP_SIGN_POS;
		p->alloc = allocsz;
		p->top = -1;

		for (i = 0; i < allocsz; i++)
			p->dig[i] = 0;

		p = va_arg(ap, mp_int *);
	}

	va_end(ap_copy);
	va_end(ap);

	return MP_OK;
nomem:
	p = a;
	while (p != NULL && cnt > 0) {
		--cnt;
		free(p->dig);
		p = va_arg(ap_copy, mp_int *);
	}
	va_end(ap_copy);
	va_end(ap);

	return MP_NOMEM;
}

