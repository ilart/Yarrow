#ifndef COMMON_H_
#define COMMON_H_

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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <sys/poll.h>

#ifndef u_int8_t
  typedef uint8_t	u_int8_t;
#endif
#ifndef u_int16_t
  typedef uint16_t	u_int16_t;
#endif
#ifndef u_int32_t
  typedef uint32_t	u_int32_t;
#endif

#endif

