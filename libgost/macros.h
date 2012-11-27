#ifndef MACROS_H_
#define MACROS_H_

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef TRUE
#define TRUE (!FALSE)
#endif

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof((x)[0]))

#define MEM_ALIGN_BITS	3
#define MEM_ALIGN(x)	(((x) + ((1 << MEM_ALIGN_BITS)-1)) & (~0UL << MEM_ALIGN_BITS))

#define CRLF	"\r\n"

#define SHOULDNT_REACH() \
do { \
	fprintf(stderr, "file %s line %d %s(): should not reach this" CRLF, \
		__FILE__, \
		__LINE__, \
		__FUNCTION__); \
	abort(); \
} while (0)

#define return_if_fail(expr) \
do { \
	if (!(expr)) { \
		fprintf(stderr, "file %s line %d %s(): expression `%s' failed" CRLF, \
			__FILE__, \
			__LINE__, \
			__FUNCTION__, \
			#expr); \
		return; \
	} \
} while (0)

#define return_val_if_fail(expr, val) \
do { \
	if (!(expr)) { \
		fprintf(stderr, "file %s line %d %s(): expression `%s' failed" CRLF, \
			__FILE__, \
			__LINE__, \
			__FUNCTION__, \
			#expr); \
		return (val); \
	} \
} while (0)

#endif /* MACROS_H_ */
