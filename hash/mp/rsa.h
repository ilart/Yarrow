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

#ifndef RSA_H_
#define RSA_H_

enum {
	RSA_EXP_F0 = 3,
	RSA_EXP_F2 = 17,
	RSA_EXP_F4 = 65537
};

/* RSAKG key generation routine */
int rsakg(unsigned int len, int exp, int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx, mp_int *n, mp_int *d);

/* RSAKG for use with CRT key generation routine */
int rsacrtkg(unsigned int len, int exp, int (*rnd)(void *buf, size_t len, void *rndctx), void *rndctx,
	     mp_int *n, mp_int *p, mp_int *q, mp_int *dp, mp_int *dq, mp_int *qinv);

/* RSAEP encryption */
int rsaep(const mp_int *m, int exp, const mp_int *n, mp_int *c);

/* RSADP decryption */
int rsadp(const mp_int *c, const mp_int *d, const mp_int *n, mp_int *m);

/* RSADP with CRT decryption */
int rsacrtdp(const mp_int *c, const mp_int *p, const mp_int *q, const mp_int *dp, const mp_int *dq, const mp_int *qinv, mp_int *m);

#endif /* RSA_H_ */

