#include "yarrow.h"
#include "hash_desc.h"
#include "macros.h"
#include "prng.h"
#include "gost.h"
#include "common.h"
#include "cipher_desc.h"
#include "feed_entropy.h"
	
struct entropy_pool fast_pool, slow_pool;
int add_to_fast[MAXSOURCES];

int main(int argc, char **argv)
{
	extern add_to_fast[MAXSOURCES];
	int res, i, fd;
	size_t size = 512;
	int buf_random[512];
	double tmp;
	struct prng_context prng;
	
	char buf[128];
	//char tmp_buf[16];
	unsigned char *tmp_s;

	memset(add_to_fast, 0, sizeof(add_to_fast));

	res = entropy_pool_init(&fast_pool, 12, HASH_SHA256);
	if (res == 0)
		printf("pool.nsources %d "
		       "pool.k %d "
		       "pool.hdesc->name %s \n",
		       fast_pool.nsources, 
		       fast_pool.k, 
		       fast_pool.hdesc->name);

	res = entropy_pool_init(&slow_pool, 17, HASH_SHA256);
	if (res == 0)
		printf("slow_pool.nsoursec  %d "
		       "slow_pool.k %d " 
		       "slow_pool.hdesc->name %s \n", 
		       slow_pool.nsources, 
		       slow_pool.k, 
		       slow_pool.hdesc->name);
	printf("\n");

	if(prng_cipher_init(CIPHER_GOST, &prng))
		printf("prng.cipher_name %s "
		       "prng.cipher_len %d "
		       "prng.cipher_key_size %d \n",
		       prng.cdesc->name,
		       prng.cdesc->block_size,
		       prng.cdesc->key_size);
	else {
		printf("Error of prng_cipher_init\n");
		return 1;
	}
	
	prng.cipher_ctx = prng.cdesc->context_new();

	if(prng_hash_init(HASH_SHA256, &prng))
		printf("prng.hash_name %s "
		       "prng.digest_len %d \n",
		       prng.hdesc->name,
		       prng.hdesc->digest_len);
				
	else {
		printf("Error of prng_hash_init\n");
		return 1;
	}

	res = entropy_pool_length(&slow_pool);
	printf("entropy_pool_lenght %u \n", res);

	res = entropy_pool_set_nsources(&fast_pool, 15);
	if (res == 0)
	        printf("entropy_pool_set_nsources %d \n", fast_pool.nsources);

	res = entropy_pool_get_nsources(&fast_pool);
	if (res != 0)
                printf("entropy_pool_get_nsources %d\n", res);
	
	res = entropy_pool_set_k(&fast_pool, 1);
	if (res == 0)
		printf("entropy_pool_set_k %d\n", fast_pool.k);

	res = entropy_pool_get_k(&fast_pool);
	if (res != 0)
                printf("entropy_pool_get_k %d\n", res);
	printf("\n");

	res = entropy_pool_set_threshold(&fast_pool, 0, 120.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in fast %f\n", fast_pool.threshold[0]);

	res = entropy_pool_set_threshold(&slow_pool, 0, 181.0);	
	if (res == 0)
                printf("entropy_pool_set_threshold in slow %f\n", slow_pool.threshold[0]);
	
	tmp = entropy_pool_get_threshold(&fast_pool, 0);	
	if (tmp != 0)
                printf("entropy_pool_get_threshold %f\n", tmp);
	printf("\n");
	
	fd = open("/dev/urandom" , O_RDONLY);
	if (fd == -1)
		perror("Error of open");

	res = read(fd, &prng.key, sizeof(prng.key));
	if (res == -1)
		perror("Error of write");

	printf("key before reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n");

	res = read(fd, buf, sizeof(buf));
	if (res < 0) {
		perror("error of read");		
	}

	prng.gate_param = 10;

	res = prng_set_time_param(&prng, 10);
	printf("prng_set_time_param %d", res);

	res = prng_get_time_param(&prng);
	printf("prng_set_time_param %d", res);

	feed_entropy(0, buf, 16, 0.5, &prng);
	feed_entropy(0, buf+16, 16, 0.5, &prng);
	feed_entropy(0, buf+32, 16, 0.5, &prng);
	feed_entropy(0, buf+48, 16, 0.5, &prng);
		

	res = entropy_pool_add(&fast_pool, 0, buf, 33, 0.5);
	if (res == 0)
		printf("pool.estimate add %f \n", 
			fast_pool.estimate[0]);
	else {
		printf("error of entropy_pool_add");
		return EPOOL_FAIL;
	}
	printf("\n");
	

	res = entropy_pool_get_nsources(&fast_pool);

//	prng_reseed(&prng, &fast_pool, 10);

	printf("\n key after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.key); i++) {
		printf("%u ", prng.key[i]);
	}
	
	printf("\n counter after reseed \n");
	for (i = 0; i < ARRAY_SIZE(prng.counter); i++) {
		printf("%u ", prng.counter[i]);
	}

	prng_encrypt(&prng, buf_random, &size);	
	printf("\nrandom values\n");
	for (i = 0; i < 512/4; i++) {
		printf(" %d, ", buf_random[i]);
	}

	res = entropy_pool_is_thresholded(&fast_pool);
	printf("thresholded = %d \n", res);

	printf("\ndigest_len %d\n", fast_pool.hdesc->digest_len);	
	
	tmp_s = entropy_pool_bytes(&slow_pool);
	printf("slow_pool_byts %s \n", tmp_s);

	entropy_pool_clean(&fast_pool);
	printf("entropy_pool_clean %s", fast_pool.buffer);


//	slow_pool.hdesc->finalize(&slow_pool, (void *)tmp_buf);
//	printf("hash = %s \n", tmp_buf);
	
	res = entropy_pool_deinit(&fast_pool);

	if (res == 0)
		printf ("fast_pool_hdesc %p,"
			"pool.nsources %d "
			"pool.k %d \n", 
			fast_pool.hdesc, 
			fast_pool.nsources, 
			fast_pool.k);


	close(fd);

	return 0;
}
