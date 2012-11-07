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

