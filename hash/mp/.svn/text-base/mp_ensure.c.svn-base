#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "mp_common.h"

/* Ensures place for new_size digits in the MP integer, resizing if necessary. */
int
mp_ensure(mp_int *p, unsigned int new_size)
{
	void *tmp;
	unsigned int allocsz;
	int i;

	if (p->alloc >= new_size)
		return MP_OK;

	/*
	 * Calculate the size rounding new_size up to MP_ALLOC_CHUNK.
	 * Additional MP_ALLOC_APPEND bytes are attached to the block
	 * to reduce overhead caused by small changes. 
	 */
	allocsz = (new_size / MP_ALLOC_CHUNK) * MP_ALLOC_CHUNK +
		  (new_size % MP_ALLOC_CHUNK ? MP_ALLOC_CHUNK : 0);
	allocsz += MP_ALLOC_APPEND;

	tmp = realloc(p->dig, allocsz * sizeof(_mp_int_t));

	if (tmp == NULL)
		return MP_NOMEM;

	p->dig = tmp;
	for (i = p->alloc; i < allocsz; i++)
		p->dig[i] = 0;
	p->alloc = allocsz;

	return MP_OK;
}

