#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "mp.h"
#include "mp_common.h"

void
mp_clear(mp_int *p)
{
	assert(p != NULL);

	if (p->dig != NULL)
		free(p->dig);
}

void
mp_clearv(mp_int *a, ...)
{
	va_list ap;

	va_start(ap, a);

	while (a != NULL) {
		if (a->dig != NULL)
			free(a->dig);
		a = va_arg(ap, mp_int *);
	}

	va_end(ap);
}

