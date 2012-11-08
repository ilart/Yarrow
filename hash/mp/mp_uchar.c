#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "mp.h"
#include "mp_common.h"

int
mp_to_uchar(const mp_int *a, unsigned char *buf, int len)
{
	int i, n, nc, ns, nb, ndig;
	_mp_int_t dig, *dp;
	unsigned char c, *bp;

	ndig = (a->top + 1);
	n = (ndig * MP_INT_BITS) / CHAR_BIT;
	n += (ndig * MP_INT_BITS) % CHAR_BIT ? 1 : 0;

	dig = ns = nc = nb = 0;
	bp = buf + len - 1;
	dp = a->dig;

	for (i = 0; i < n; i++) {

		c = 0;

		if (len == 0)
			break;

		while (nc < CHAR_BIT) {

			if (nb <= 0) {
				dig = *dp++;
				nb = MP_INT_BITS;
				--ndig;
			}

			if (ndig == 0 && dig == 0) {
				*bp = c;
				goto done;
			}

			ns = CHAR_BIT - nc;

			if (nb >= ns) {
				c |= (dig & ((1 << ns)-1)) << nc;
				nb -= ns;
				dig >>= ns;
				*bp-- = c;
				nc = 0;
				break;
			} else {
				c |= dig << nc;
				nc += nb;
				nb = 0;
			}
		}

		--len;
	}

done:
	return MP_OK;
}

int
mp_set_uchar(mp_int *a, const unsigned char *buf, int len)
{
	_mp_int_t *dig;
	int i, ndig, rc, nb, nc, ns;
	int nbits, oldtop;
	unsigned char c;
	const unsigned char *bp;

	ndig = (len * CHAR_BIT) / MP_INT_BITS;
	ndig += (len * CHAR_BIT) % MP_INT_BITS ? 1 : 0;
	nbits = len * CHAR_BIT;

	rc = mp_ensure(a, ndig);
	if (rc != MP_OK)
		return rc;
	
	oldtop = a->top;
	a->top = ndig - 1;
	a->sign = MP_SIGN_POS;
	dig = a->dig;
	bp = buf + len - 1;

	c = ns = nb = nc = 0;

	while (nbits > 0) {

		nb = (nbits >= MP_INT_BITS) ? MP_INT_BITS : nbits;
		ns = nb;

		*dig = 0;
			
		while (nb > 0) {

			if (nc <= 0) {
				c = *bp--;
				nc = CHAR_BIT;
			}

			if (nb >= nc) {
				*dig |= c << (ns - nb);
				nb -= nc;
				nbits -= nc;
				nc = 0;
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

	return MP_OK;
}

