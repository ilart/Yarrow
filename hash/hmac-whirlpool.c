/*
 * HMAC-Whirlpool -- HMAC and PBKDF2 based on Whirlpool hash.
 *
 * Implements HMAC and PBKDF2 PKCS #5 v2.0 RFC 2898.
 *
 * Grisha Sitkarev, <sitkarev@unixkomi.ru> 2011 (c)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "whirlpool.h"
#include "hmac-whirlpool.h"

#define BLOCKSIZE	64

#define PBKDF2_DEFAULT_NITER	1024

/*
 * HMAC implementation as defined by RFC 2104.
 *
 * H    - cryptographic function
 * K    - secret key padded with extra zeros to the right
 * m    - message to be authenticated
 * ||   - concatenation
 * xor  - exclusive or (XOR)
 * opad - 0x5c5c5c...5c5c one-block long
 * ipad - 0x363636...3636 one-block long
 *
 * HMAC(K,m) = H((K xor opad) || H((K xor ipad) || m)).
 *
 * This implementation uses WHIRLPOOL hash. The resulting HMAC is placed into
 * 64-byte buffer.
 */

void
hmac_whirlpool(const void *key, unsigned nkey, const void *msg, unsigned nmsg, unsigned char hmac[64])
{
	unsigned char buf[BLOCKSIZE];	/* key buffer */
	unsigned char ipad[BLOCKSIZE];	/* inner padding */
	unsigned char opad[BLOCKSIZE];	/* outer padding */
	struct whirlpool_context ctx;	/* reusable hash function context */
	uint32_t *p, *p2;
	int i;

	if (nkey > BLOCKSIZE) {
		whirlpool_context_init(&ctx);
		whirlpool_update(&ctx, key, nkey);
		whirlpool_final(&ctx, buf);
	} else {
		memset(buf, 0, sizeof(buf));
		memcpy(buf, key, nkey);
	}

	p = (uint32_t *) ipad;
	p2 = (uint32_t *) buf;
	for (i = 0; i < (BLOCKSIZE / sizeof(uint32_t)); i++)
		*p++ = *p2++ ^ 0x5c5c5c5c;
	p = (uint32_t *) opad;
	p2 = (uint32_t *) buf;
	for (i = 0; i < (BLOCKSIZE / sizeof(uint32_t)); i++)
		*p++ = *p2++ ^ 0x36363636;

	whirlpool_context_init(&ctx);
	whirlpool_update(&ctx, ipad, BLOCKSIZE);
	whirlpool_update(&ctx, msg, nmsg);
	whirlpool_final(&ctx, ipad);

	whirlpool_context_init(&ctx);
	whirlpool_update(&ctx, opad, BLOCKSIZE);
	whirlpool_update(&ctx, ipad, BLOCKSIZE);
	whirlpool_final(&ctx, hmac);
}

/*
 * PKCS #5 v2.0 PBKDF2 implementation as defined by RFC 2898.
 * 
 * This implementation uses HMAC-Whirlpool as PRF.
 */

void *
pbkdf2_hmac_whirlpool(const void	*pass,
		      unsigned		npass,
		      const void	*salt,
		      unsigned		nsalt,
		      int		niter,
		      void		*key,
		      unsigned		nkey)
{
	unsigned char u[BLOCKSIZE+4], u2[BLOCKSIZE];
	unsigned char *out, *p, *p2;
	unsigned c, j, i, l, n;

	if (key == NULL || nkey == 0 || pass == NULL || npass == 0)
		return NULL;

	if (salt == NULL || nsalt == 0 || nsalt > BLOCKSIZE)
		return NULL;

	if (niter == 0)
		niter = PBKDF2_DEFAULT_NITER;

	c = niter;
	out = key;
	l = nkey / BLOCKSIZE;
	l += (nkey % BLOCKSIZE) ? 1 : 0;

	for (i = 0; i < l; i++) {

		/* T_i = U_0 xor U_1 xor U_2 xor ... xor U_{c-1}.  */

		/*
		 * Construct the message for the PRF iteration. It is a
		 * concatenation of a salt and an iteration number in MSB first
		 * order.
		 */
		memcpy(u, salt, nsalt);
		u[nsalt]   = (i & 0xff000000) >> 24;
		u[nsalt+1] = (i & 0xff0000) >> 16;
		u[nsalt+2] = (i & 0xff00) >> 8;
		u[nsalt+3] = i & 0xff;

		hmac_whirlpool(pass, npass, u, nsalt+4, u);
	
		/* p and p2 are pointers to current U_1 and previous U_0 blocks */
		p  = u2;
		p2 = u;

		for (j = 0; j < c-1; j++) {
			uint32_t *s, *s2;
			unsigned char *tmp;

			/* Apply PRF to U_{j-1} to derive U_j. */
			hmac_whirlpool(pass, npass, p2, BLOCKSIZE, p);

			/* XOR U_{j-1} and U_j. */
			s = (uint32_t *) p; s2 = (uint32_t *) p2;
			for (n = 0; n < BLOCKSIZE / sizeof(uint32_t); n += 4) {
				*s++ ^= *s2++;
				*s++ ^= *s2++;
				*s++ ^= *s2++;
				*s++ ^= *s2++;
			}

			/* 
			 * Swap pointers to blocks and store an address of U_{j-1}
			 * in p and an address of U_j in p2. At the next iteration
			 * where we will derive U_{j+1}, U_i is used as a previous
			 * block input to PRF and U_{j-1} is rewritten by U_{j+1}.
			 */
			tmp = p;
			p   = p2;
			p2  = tmp;
		}

		/* 
		 * Store a block of a derived key T_i. Note that we copy only r
		 * bytes of the last block into the key, where r is equal to:
		 * 
		 * r = klen - (l - 1) * BLOCKSIZE.
		 */
		n = (nkey >= BLOCKSIZE) ? BLOCKSIZE : nkey;
		memcpy(out, p2,  n);
		nkey -= n;
		out += n;
	}

	return key;
}

#if 0

int
main(int argc, char *argv[])
{
	char *pass = "my message";
	unsigned char salt[8] = { 0x12, 0x8a, 0x91, 0x3f, 0x22, 0x4a, 0x73, 0x9d };
	unsigned char hmac[BLOCKSIZE];
	unsigned char dkey[32];
	int i;

	if (argc > 1)
		pass = argv[1];

	hmac_whirlpool(pass, strlen(pass), salt, 8, hmac);

	printf("HMAC-WHIRLPOOL(%s)=\n", pass);
	for (i = 0; i < BLOCKSIZE; ) {
		printf("\t%02x%02x%02x%02x%02x%02x%02x%02x",
		       hmac[i], hmac[i+1], hmac[i+2], hmac[i+3],
		       hmac[i+4], hmac[i+5], hmac[i+6], hmac[i+7]);
		i += 8;
		printf("%02x%02x%02x%02x%02x%02x%02x%02x\n",
		       hmac[i], hmac[i+1], hmac[i+2], hmac[i+3],
		       hmac[i+4], hmac[i+5], hmac[i+6], hmac[i+7]);
		i += 8;

	}
	printf("\n");

	pbkdf2_hmac_whirlpool(pass, strlen(pass), salt, 8, 4096, dkey, sizeof(dkey));

	printf("PBKDF2-HMAC-WHIRLPOOL(%s)=\n", pass);
	for (i = 0; i < sizeof(dkey); ) {
		printf("\t%02x%02x%02x%02x%02x%02x%02x%02x",
		       dkey[i], dkey[i+1], dkey[i+2], dkey[i+3],
		       dkey[i+4], dkey[i+5], dkey[i+6], dkey[i+7]);
		i += 8;
		printf("%02x%02x%02x%02x%02x%02x%02x%02x\n",
		       dkey[i], dkey[i+1], dkey[i+2], dkey[i+3],
		       dkey[i+4], dkey[i+5], dkey[i+6], dkey[i+7]);
		i += 8;
	}

	return 0;
}

#endif

