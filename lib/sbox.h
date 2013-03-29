#ifndef SBOX_H_
#define SBOX_H_

extern unsigned char rijndael_sbox[256];
extern unsigned char rijndael_isbox[256];

void rijndael_sbox_init();
void rijndael_sbox_print();

#endif /* SBOX_H_ */

