#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "mp.h"
#include "rsa.h"
#include "emeoaep.h"

int
urandom(void *buf, size_t len)
{
	int fd, res;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return -1;
	res = read(fd, buf, len);
	close(fd);
	return res;
}

static int
rnd(void *buf, size_t len, void *ctx)
{
	return urandom(buf, len);
}

int
test_gcd()
{
	mp_int a, b, c;
	int rc;

	mp_initv(&a, &b, &c, NULL);

	mp_set_str(&a, "65536", 10);
	mp_set_str(&b, "4", 10);

	rc = mp_gcd(&c, &a, &b);
	if (rc != MP_OK)
		goto err;

	mp_dbg(&c, stdout);
err:
	mp_clearv(&a, &b, &c, NULL);
	return 0;
}

static int 
testrnd(void *buf, size_t len, void *ctx)
{
	unsigned char rnd[] = { 
		0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34,
		0x89, 0xb4, 0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2,
		0xf0, 0x6c, 0xb5, 0x8f
	};
	memcpy(buf, rnd, len);
	return len;
}

int
test_sha1_oaep()
{
	char *rsakey =
		"bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a4"
		"40d6b6f07454f51fb8dfbaaf035c02ab61ea48ceeb6fcd48"
		"76ed520d60e1ec4619719d8a5b8b807fafb8e0a3dfc73772"
		"3ee6b4b7d93a2584ee6a649d060953748834b2454598394e"
		"e0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f59"
		"46f8e5fd091dbdcb";

	unsigned char msg[] = { 
		0xd4, 0x36, 0xe9, 0x95, 0x69, 0xfd, 0x32, 0xa7,
		0xc8, 0xa0, 0x5b, 0xbc, 0x90, 0xd3, 0x2c, 0x49 
	};

	unsigned char enc[127];
	unsigned char buf[1024];
	mp_int n, m, c;
	int i, rc;

	mp_initv(&n, &m, &c, NULL);

	emeoaep_sha1_encode(msg, sizeof(msg), NULL, 0, testrnd, NULL, enc, sizeof(enc));

	printf("EMEOAEP-SHA1-Encode()=");
	for (i = 0; i < sizeof(enc); i++) {
		printf("%02x ", enc[i]);
	}
	printf("\n");

	mp_set_str(&n, rsakey, 16);	
	mp_set_uchar(&m, enc, 127);

	rsaep(&m, RSA_EXP_F2, &n, &c);

	mp_to_uchar(&c, buf, 128);

	printf("RSA ciphertext()=\n");
	for (i = 0; i < 128; i += 16) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			buf[i], buf[i+1], buf[i+2], buf[i+3],
			buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x",
			buf[i+8], buf[i+9], buf[i+10], buf[i+11],
			buf[i+12], buf[i+13], buf[i+14], buf[i+15]);
		printf("\n");
	}


	emeoaep_sha1_decode(enc, sizeof(enc), buf, sizeof(msg), NULL);

	printf("EMEOAEP-SHA1-Decode()=");
	for (i = 0; i < sizeof(msg); i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");

	mp_clearv(&n, &m, &c, NULL);

	return 0;
}

int
test_rsacrt()
{
	char *message = "Hello, RSA! :)) Yes, it works!";
	char buf[1024];
	char dec[511], enc[511];
	mp_int c, m, n, p, q, dp, dq, qinv;
	int rc;

	rc = mp_initv(&c, &m, &n, &p, &q, &dp, &dq, &qinv, NULL);

	printf("m()=%s\n", message);

	emeoaep_sha256_encode(message, strlen(message), NULL, 0, rnd, NULL, enc, sizeof(enc));
	mp_set_uchar(&m, enc, sizeof(enc));

	rc = rsacrtkg(512, RSA_EXP_F4, rnd, NULL, &n, &p, &q, &dp, &dq, &qinv);
	if (rc != MP_OK) {
		fprintf(stderr, "rsacrtkg\n");
		exit(1);
	}

	mp_dbg(&n, stdout);

	rc = rsaep(&m, RSA_EXP_F4, &n, &c);
	if (rc != MP_OK) {
		fprintf(stderr, "rsaep\n");
		exit(1);
	}

	mp_zero(&m);

	rc = rsacrtdp(&c, &p, &q, &dp, &dq, &qinv, &m);
	if (rc != MP_OK) {
		fprintf(stderr, "rsacrtdp\n");
		exit(1);
	}

	mp_to_uchar(&m, dec, sizeof(dec));
	emeoaep_sha256_decode(dec, sizeof(dec), buf, strlen(message), NULL);

	buf[strlen(message)] = '\0';
	printf("M()=%s\n", buf);
	
	mp_clearv(&c, &m, &n, &p, &q, &dp, &dq, &qinv, NULL);
	return rc;
}

int
test_rsa()
{
	char *message = "Hello, RSA! :)) Yes, it works!";
	unsigned char buf[1024];
	unsigned char pubkey[128], privkey[128];
	char dec[127], enc[127];
	mp_int c, m, public_key, private_key;
	int i, rc;

	/* initialize Multiple Precision integers */
	mp_initv(&c, &m, &public_key, &private_key, NULL);

	/* generate RSA keypair */
	rsakg(128, RSA_EXP_F4, rnd, NULL, &public_key, &private_key);

	/* save RSA keys into buffers */
	mp_to_uchar(&public_key, pubkey, 128);
	mp_to_uchar(&private_key, privkey, 128);

	printf("RSA Private Key=\n");
	for (i = 0; i < 128; i += 16) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			privkey[i], privkey[i+1], privkey[i+2], privkey[i+3],
			privkey[i+4], privkey[i+5], privkey[i+6], privkey[i+7]);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x",
			privkey[i+8], privkey[i+9], privkey[i+10], privkey[i+11],
			privkey[i+12], privkey[i+13], privkey[i+14], privkey[i+15]);
		printf("\n");
	}

	printf("RSA Public Key=\n");
	for (i = 0; i < 128; i += 16) {
		printf("%02x %02x %02x %02x %02x %02x %02x %02x ",
			pubkey[i], pubkey[i+1], pubkey[i+2], pubkey[i+3],
			pubkey[i+4], pubkey[i+5], pubkey[i+6], pubkey[i+7]);
		printf("%02x %02x %02x %02x %02x %02x %02x %02x",
			pubkey[i+8], pubkey[i+9], pubkey[i+10], pubkey[i+11],
			pubkey[i+12], pubkey[i+13], pubkey[i+14], pubkey[i+15]);
		printf("\n");
	}

	/* encryption/decryption examples */

	printf("m()=%s\n", message);

	/* encode the message (up to 127 bytes) using OAEP scheme */
	emeoaep_sha256_encode(message, strlen(message), NULL, 0, rnd, NULL, enc, 127);

	/* convert encoded message into MP integer representation */
	mp_set_uchar(&m, enc, 127);

	/* convert public key into MP integer */
	mp_set_uchar(&public_key, pubkey, 128);

	/* encrypt the message using public key */
	rsaep(&m, RSA_EXP_F4, &public_key, &c);

	/* reset the message */
	mp_zero(&m);

	/* convert private key into MP integer */
	mp_set_uchar(&private_key, privkey, 128);

	/* decrypt ciphertext using public and private keys */
	rsadp(&c, &private_key, &public_key, &m);

	/* decode the message using OAEP scheme */
	mp_to_uchar(&m, dec, 127);
	emeoaep_sha256_decode(dec, 127, buf, strlen(message), NULL);

	buf[strlen(message)] = '\0';
	printf("M()=%s\n", buf);
	
	/* release resources */
	mp_clearv(&c, &m, &public_key, &private_key, NULL);
	return rc;
}

int
main(int argc, char *argv[])
{
	test_rsa(); 

	//test_rsacrt();
	//test_gcd();

	test_sha1_oaep();

//	test_rsaep();

	return 0;
}

