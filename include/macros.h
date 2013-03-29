#ifndef MACROS_H_
#define MACROS_H_

#ifndef FALSE
#define FALSE	0
#endif
#ifndef TRUE
#define TRUE	(!FALSE)
#endif

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof((x)[0]))

#ifndef NDEBUG
#define DEBUG_ONLY(x)	x
#else
#define DEBUG_ONLY(x)	
#endif

#ifndef NDEBUG
#define return_if_fail(expr) \
{ \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d:%s(): expression `%s' failed\n", \
			__FILE__, \
			__LINE__, \
			__FUNCTION__, \
			#expr); \
		return; \
	} \
}

#define return_val_if_fail(expr, val) \
{ \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d:%s(): expression `%s' failed\n", \
			__FILE__, \
			__LINE__, \
			__FUNCTION__, \
			#expr); \
		return (val); \
	} \
}

/*#define assert(expr) \
{ \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d:%s(): Assertion (%s) failed\n", \
			__FILE__, \
			__LINE__, \
			__FUNCTION__, \
			#expr); \
		abort(); \
	} \
}
*/
#else
#define return_if_fail(expr)
#define return_val_if_fail(expr, val)
#define assert(expr)
#endif

#endif

