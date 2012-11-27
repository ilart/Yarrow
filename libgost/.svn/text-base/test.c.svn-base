#include "common.h"

#include "macros.h"
#include "gost.h"

int
main(int argc, char *argv[])
{
	struct gost_context *enc, *dec;
	int i;

	u_int32_t key[] = {
		0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff,
		0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00
	};

	u_int8_t msg[] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04
	};

	u_int32_t sync[] = { 0xdeadbeef, 0xbabe0102 };
	u_int32_t sync2[] = { 0xdeadbeef, 0xbabe0102 };

	char text[] = "Test me, test me. I am GOST :)";
	int n;

	enc = gost_context_new();
	dec = gost_context_new();

	gost_set_key(enc, key);
	gost_set_key(dec, key);

	gost_set_sbox(enc, NULL);
	gost_set_sbox(dec, NULL);

	gost_set_sync(enc, sync);
	gost_set_sync(dec, sync2);

	gost_encrypt_32z(enc, (u_int32_t *) msg);

	printf("32Z: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	       msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7]);

	gost_decrypt_32r(dec, (u_int32_t *) msg);

	printf("32R: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	       msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7]);

	n = strlen(text);
	gost_apply_gamma(enc, (u_int8_t *)text, n);

	printf("Encrypted %d bytes:\n", n);
	for (i = 0; i < n; i++) {
		printf(" %02x", ((u_int8_t*)text)[i]);
	}
	printf("\n");

	gost_apply_gamma(dec, (u_int8_t *)text, n);

	printf("Message %d bytes: %s\n", n, text);

	gost_context_free(&enc);
	gost_context_free(&dec);

	return 0;
}

