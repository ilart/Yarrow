#ifndef COMMON_H_
#define COMMON_H_

#include <stdint.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#elif defined __FreeBSD__
#include <sys/mman.h>
#elif defined _WIN32
#include <sys/stat.h>
#include <windows.h>
#include <io.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifdef __FreeBSD__
#include <machine/endian.h>
#elif defined(_WIN32)
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER __LITTLE_ENDIAN
#elif defined __linux__
#include <endian.h>
#else
#error unsupported system type
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif

#ifndef u_int8_t
typedef uint8_t		u_int8_t;
#endif
#ifndef u_int16_t
typedef uint16_t	u_int16_t;
#endif
#ifndef u_int32_t
typedef uint32_t	u_int32_t;
#endif

#endif

