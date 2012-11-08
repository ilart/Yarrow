#ifndef MP_COMMON_H_
#define MP_COMMON_H_

#define MP_ALLOC_CHUNK		64
#define MP_ALLOC_DEFAULT	MP_ALLOC_CHUNK
#define MP_ALLOC_APPEND		8

#define MP_KARATSUBA_CUTOFF	80

#define MP_COMBA_DEPTH		256
#define MP_COMBA_STACK		1024

#define MIN(a, b)		((a) > (b) ? (b) : (a))
#define MAX(a, b)		((a) > (b) ? (a) : (b))

#ifndef NDEBUG
#define MP_DEBUG(fmt, arg...)	{ fprintf(stderr, "MPDBG: " fmt "\n", ##arg); fflush(stderr); }
#else
#define MP_DEBUG(fmt, arg...)
#endif

int mp_ensure(mp_int *p, unsigned int new_size);

#endif

