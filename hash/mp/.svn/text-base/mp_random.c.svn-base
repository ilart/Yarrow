#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "mp.h"
#include "mp_common.h"

int
mp_random(mp_int *a, int size,
	  int (*rnd)(void *buf, size_t size, void *rndctx),
	  void *rndctx)
{
	unsigned char buf[1024], *bufptr;
	_mp_int_t *dig;
	int i, nb, nc, rc, ns;
	int nbuf, ndig, oldtop;
	int nbits;
	unsigned char c;

	rc = MP_ERR;
	ndig = (size * CHAR_BIT) / MP_INT_BITS;
	ndig += (size * CHAR_BIT) % MP_INT_BITS ? 1 : 0;

	nbits = size * CHAR_BIT;

	if ((rc = mp_ensure(a, ndig)) != MP_OK)
		return rc;

	oldtop = a->top;
	a->top = ndig-1;
	a->sign = MP_SIGN_POS;
	dig = a->dig;

	c = ns = nb = nc = nbuf = 0;
	bufptr = NULL;

	while (nbits > 0) {

		nb = (nbits >= MP_INT_BITS) ? MP_INT_BITS : nbits;
		ns = nb;

		*dig = 0;
			
		while (nb > 0) {

			if (nc <= 0) {

				if (nbuf <= 0) {
					int nread, res;

					nread = (size >= sizeof(buf)) ? sizeof(buf) : size;

					res = (*rnd)(buf, nread, rndctx);

					if (res == -1)
						goto out;

					nbuf = nread;
					bufptr = buf;
				}

				c = *bufptr++;

				/*
				 * Last random byte is required to have two top
				 * bits set. This guarantees that the
				 * multiplication of two such values will always
				 * produce carry to the top bit of the result.
				 */
				if (size == 1)
					c |= 0xc0;

				nc = CHAR_BIT;
				--nbuf;
			}

			if (nb >= nc) {
				*dig |= c << (ns - nb);
				nb -= nc;
				nbits -= nc;
				nc = 0;
				--size;
			} else {
				*dig |= (c & ((1 << nb)-1)) << (ns - nb);
				nc -= nb;
				nbits -= nb;
				c >>= nb;
				nb = 0;
			}
		}

		++dig;
	}

	for (i = ndig; i <= oldtop; i++)
		*dig++ = 0;

	rc = MP_OK;
out:
	return rc;
}

