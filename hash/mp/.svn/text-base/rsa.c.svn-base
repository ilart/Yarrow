/*
 * RSA -- Asymmetric Encryption Algorithm.
 *
 * Grisha Sitkarev, 2011 (c)
 * <sitkarev@unixkomi.ru>
 *
 * For details please refere to:
 *
 * R. Rivest, A. Shamir and L. Adleman. A Method for Obtaining Digital
 * Signatures and Public-Key Cryptosystems. Communications of the ACM,
 * 21 (2), pp. 120-126, February 1978.
 *
 * RSA Laboratories. PKCS #1 v2.1: RSA Encryption Standard. June 2002. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mp.h"
#include "rsa.h"

#define RSAKG_TRIES_MAX			2000
#define RSAKG_MILLER_RABIN_PARAM	8

static int
rsa_rnd_prime(const mp_int *exp, int len, int triesmax, int param,
	      int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
	      mp_int *prime)
{
	mp_int gcd, one;
	int rc, cnt;

	if ((rc = mp_initv(&gcd, &one, NULL)) != MP_OK)
		return rc;

	mp_set_one(&one);

	for (cnt = 0; cnt < triesmax; cnt++) {

		rc = mp_random(prime, len, rnd, rndctx);
		if (rc != MP_OK)
			goto err;
		
		if (mp_iseven(prime)) {
			rc = mp_add(prime, prime, &one);
			if (rc != MP_OK)
				goto err;
		}

		rc = mp_primality_miller_rabin(prime, param, rnd, rndctx);

		if (rc == MP_OK) {

			rc = mp_gcd(&gcd, prime, exp);
			if (rc != MP_OK)
				goto err;

			if (mp_cmp(&gcd, &one) == MP_CMP_EQ)
				break;
		}
	}

	if (cnt >= triesmax)
		rc = MP_ERR;
	else
		rc = MP_OK;

err:
	mp_clearv(&gcd, &one, NULL);
	return rc;
}

/*
 * RSAKG -- RSA key pair generation routine.
 *
 * len: length if the key in bytes
 * exp: RSA_EXP_F0, RSA_EXP_F2 or RSA_EXP_F4
 * n: MP integer where the public key is output
 * d: MP integer where the private key is output
 *
 * Returns: MP_OK on success
 */
int
rsakg(unsigned int len, int exp,
      int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
      mp_int *n, mp_int *d)
{
	mp_int e, p, q;
	mp_int phi, one;
	int rc, len2;

	if (n == NULL || d == NULL)
		return -1;

	switch (exp) {
	case RSA_EXP_F0:
	case RSA_EXP_F2:
	case RSA_EXP_F4:
		break;
	default:
		return -1;
	}

	rc = mp_initv(&e, &p, &q, &phi, &one, NULL);
	if (rc != MP_OK)
		return rc;

	mp_set_uint(&e, exp);
	mp_set_one(&one);

	len2 = len / 2;

	rc = rsa_rnd_prime(&e, len2, RSAKG_TRIES_MAX, RSAKG_MILLER_RABIN_PARAM,
			   rnd, rndctx, &p);
	if (rc != MP_OK)
		goto err;

	rc = rsa_rnd_prime(&e, len2, RSAKG_TRIES_MAX, RSAKG_MILLER_RABIN_PARAM,
			   rnd, rndctx, &q);
	if (rc != MP_OK)
		goto err;

	/* public_key = p * q. */
	rc = mp_mul(n, &p, &q);
	if (rc != MP_OK)
		goto err;

	rc = mp_sub(&p, &p, &one);
	if (rc != MP_OK)
		goto err;

	rc = mp_sub(&q, &q, &one);
	if (rc != MP_OK)
		goto err;

	/* phi = (p-1)(q-1). */
	rc = mp_mul(&phi, &q, &p);
	if (rc != MP_OK)
		goto err;

	/* private_key is a modular inverse of e mod phi. */
	rc = mp_mod_inv(d, &e, &phi);
	if (rc != MP_OK)
		goto err;

	rc = MP_OK;
err:
	mp_clearv(&e, &p, &q, &phi, &one, NULL);
	return rc;
}

/*
 * RSAEP -- RSA encryption primitive.
 *
 * m: MP integer representation of the message to be encrypted
 * exp: RSA_EXP_F0, RSA_EXP_F2 or RSA_EXP_F4
 * n: MP integer representation of the public key
 * c: MP integer representation of the ciphertext
 *
 * Returns: MP_OK on success
 */

int
rsaep(const mp_int *m, int exp, const mp_int *n, mp_int *c)
{
	int rc;
	mp_int e;

	if (m == NULL || c == NULL || n == NULL)
		return -1;

	switch (exp) {
	case RSA_EXP_F0:
	case RSA_EXP_F2:
	case RSA_EXP_F4:
		break;
	default:
		return -1;
	}

	if (mp_cmp(m, n) != MP_CMP_LT)
		return -1;

	rc = mp_init(&e);
	if (rc != MP_OK)
		return rc;

	mp_set_uint(&e, exp);

	rc = mp_mod_exp(c, m, &e, n);

	mp_clear(&e);
	return rc;
}

/*
 * RSADP -- RSA decryption primitive.
 *
 * c: MP integer representation of the ciphertext
 * exp: RSA_EXP_F0, RSA_EXP_F2 or RSA_EXP_F4
 * private_key: MP integer representation of the private key
 * public_key: MP integer representation of the public key
 * m: MP integer representation of the decrypted message
 * 
 * m = c^d mod n
 *
 * Returns: MP_OK on success
 */

int
rsadp(const mp_int *c, const mp_int *d, const mp_int *n, mp_int *m)
{
	int rc;

	if (c == NULL || m == NULL || d == NULL || n == NULL)
		return -1;

	if (mp_cmp(m, n) != MP_CMP_LT)
		return -1;

	rc = mp_mod_exp(m, c, d, n);

	return rc;
}

int
rsacrtkg(unsigned int len, int exp, int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
	 mp_int *n, mp_int *p, mp_int *q, mp_int *dp, mp_int *dq, mp_int *qinv)
{
	mp_int e, one, tmp;
	int rc, len2;

	if (n == NULL || p == NULL || q == NULL ||
	    dp == NULL || dq == NULL || qinv == NULL)
		return -1;
	
	switch (exp) {
	case RSA_EXP_F0:
	case RSA_EXP_F2:
	case RSA_EXP_F4:
		break;
	default:
		return -1;
	}

	rc = mp_initv(&e, &one, &tmp, NULL);
	if (rc != MP_OK)
		return rc;

	mp_set_uint(&e, exp);
	mp_set_one(&one);

	len2 = len / 2;

	rc = rsa_rnd_prime(&e, len2, RSAKG_TRIES_MAX, RSAKG_MILLER_RABIN_PARAM,
			   rnd, rndctx, p);
	if (rc != MP_OK)
		goto err;

	rc = rsa_rnd_prime(&e, len2, RSAKG_TRIES_MAX, RSAKG_MILLER_RABIN_PARAM,
			   rnd, rndctx, q);
	if (rc != MP_OK)
		goto err;

	/* public key n = p * q */
	rc = mp_mul(n, p, q);
	if (rc != MP_OK)
		goto err;

	/* p > q ? then swap them */
	if (mp_cmp(p, q) == MP_CMP_LT)
		mp_swap(p, q);

	/* tmp = p - 1 */
	rc = mp_sub(&tmp, p, &one);
	if (rc != MP_OK)
		goto err;

	/* dP = e^-1 (mod p-1) */
	rc = mp_mod_inv(dp, &e, &tmp);
	if (rc != MP_OK)
		goto err;

	/* tmp = q - 1 */
	rc = mp_sub(&tmp, q, &one);
	if (rc != MP_OK)
		goto err;

	/* dQ = e^-1 (mod q-1) */
	rc = mp_mod_inv(dq, &e, &tmp);
	if (rc != MP_OK)
		goto err;

	/* qInv = q^-1 (mod p) */
	rc = mp_mod_inv(qinv, q, p);
	if (rc != MP_OK)
		goto err;
	
	rc = MP_OK;
err:
	mp_clearv(&e, &one, &tmp, NULL);
	return rc;
}

int
rsacrtdp(const mp_int *c, const mp_int *p, const mp_int *q, const mp_int *dp,
	 const mp_int *dq, const mp_int *qinv, mp_int *m)
{
	mp_int m1, m2, h, mu, tmp;
	int rc;

	if (c == NULL || p == NULL || q == NULL || 
	    dp == NULL || dq == NULL || qinv == NULL || m == NULL)
		return -1;
	
	if ((rc = mp_initv(&m1, &m2, &h, &mu, &tmp, NULL)) != MP_OK)
		return rc;

	rc = mp_reduce_barrett_setup(&mu, q);
	if (rc != MP_OK)
		goto err;

	rc = mp_reduce_barrett(&tmp, c, q, &mu);
	if (rc != MP_OK)
		goto err;

	/* m2 = с^dQ mod q */
	rc = mp_mod_exp(&m2, &tmp, dq, q);
	if (rc != MP_OK)
		goto err;

	rc = mp_reduce_barrett_setup(&mu, p);
	if (rc != MP_OK)
		goto err;

	rc = mp_reduce_barrett(&tmp, c, p, &mu);
	if (rc != MP_OK)
		goto err;

	/* m1 = c^dP mod p */
	rc = mp_mod_exp(&m1, &tmp, dp, p);
	if (rc != MP_OK)
		goto err;

	/* h = (m1 - m2)*qInv (mod p) */
	rc = mp_sub(&h, &m1, &m2);
	if (rc != MP_OK)
		goto err;

	while (mp_isneg(&h)) {
		rc = mp_add(&h, &h, p);
		if (rc != MP_OK)
			goto err;
	}
	
	rc = mp_mul(&h, &h, qinv);
	if (rc != MP_OK)
		goto err;

	rc = mp_reduce_barrett(&h, &h, p, &mu);
	if (rc != MP_OK)
		goto err;

	/* m = m2 + h*q */
	rc = mp_mul(m, &h, q);
	if (rc != MP_OK)
		goto err;

	rc = mp_add(m, m, &m2);
	if (rc != MP_OK)
		goto err;

	rc = MP_OK;
err:
	mp_clearv(&m1, &m2, &h, &mu, &tmp, NULL);
	return rc;
}

