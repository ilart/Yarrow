#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>
#include <time.h>

int cnt_one = 0;
int cnt_zero = 0;

void 
monobit_test(char *str, int len)
{
	int i, d, t;
	char tmp[2], *endptr;
	float f;
	long val;
	cnt_zero = cnt_one = 0;
        tmp[2] = 0;
	for (i = 0; i < len; i += 2) {
		val = 0;
		endptr = NULL;
		tmp[0] = str[i];
		tmp[1] = str[i+1];
		val = strtol(tmp, &endptr, 16);

		while (val) {
			d = val / 2;
			t = val % 2;
			if (t)
				cnt_one++;
			else 
				cnt_zero++;
			val = d;
		}
	}
	f = (cnt_one - cnt_zero) * (cnt_one - cnt_zero) / (cnt_one + cnt_zero);
	printf("count of one = %d\n count of zero = %d\n X1 = %f \n", cnt_one, cnt_zero, f);
}

void
serial_test(unsigned char *str, int len)
{
	int i, sum, sum_sqrt, r, k, cnt_00, cnt_01, cnt_10, cnt_11;
	char tmp[2], *endptr;
	float f;
	long val;

	cnt_00 = cnt_01 = cnt_10 = cnt_11 = 0;
	
	for (i = 0; i < len; i += 2) {
		val = 0;
		endptr = NULL;
		tmp[0] = str[i];
		tmp[1] = str[i+1];
		val = strtol(tmp, &endptr, 16);

		for (k = 0; k < 4; k++) {
			r = (val << k*2) >> 6;
			switch (r) {
			case 0:
				cnt_00++;
				break;
			case 1:
				cnt_01++;
				break;
			case 2:
				cnt_10++;
				break;
			case 3: 
				cnt_11++;
				break;
			default:
				break;
			}
		}
	}
	printf("cnt_00 = %d\ncnt_01 = %d\n"
	       "cnt_10 = %d\ncnt_11 = %d\n",
	       cnt_00, cnt_01, cnt_10, cnt_11);
	sum = cnt_00 + cnt_01 + cnt_10 + cnt_11;
	sum_sqrt = cnt_00*cnt_00 + cnt_01*cnt_01 + cnt_10*cnt_10 + cnt_11*cnt_11;
	f = 4/(sum-1) * (sum_sqrt) - 2/sum * (cnt_one*cnt_one + cnt_zero*cnt_zero) + 1;
	printf("X2 %f\n", f);
}

void 
poker_test(unsigned char *str, int len)
{
	int sum, i, m, k, r, t, cnt[16];
	float f;
	char tmp[2], *endptr;
	long val;

	memset(cnt, 0, sizeof(cnt));
	
	for (i = 0; i < len; i += 2) {
		val = 0;
		endptr = NULL;
		tmp[0] = str[i];
		tmp[1] = str[i+1];
		val = strtol(tmp, &endptr, 16);
		
		for (t = 0; t < 2; t++) {
			r = (val << t*4) >> 4;
			cnt[r] += 1;	
		}
	}

	m = 4;
	sum = 0;
	for (i = 0; i < 16; i++) {
		printf("cnt[%d] = %d\n", i, cnt[i]);
		sum += cnt[i]*cnt[i];
	}
	k = (cnt_zero + cnt_one) / m;
	f = (16/k) * sum - k;
	printf("X3 = %f\n", f);
	
}

/* create client connection */
int sock_unix_connect(const char *path)
{
	int res, sock, len;
	struct sockaddr_un addr;

	if (!path)
		perror("path NULL");

	printf("path %s\n", path);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	len = strlen(path);
	memcpy(addr.sun_path, path, len);
	addr.sun_path[len] = '\0';

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
	 	printf("sock_unix_connect: socket() '%s': %s\n", path, strerror(errno));
		return -1;
	}
	printf("sock %d\n", sock);
	res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (res == -1) {
		do {
			res = close(sock);
		} while (res == -1 && errno == EINTR);
		printf("sock_unix_connect: connect() '%s': %s\n", path, strerror(errno));
		return -1;
	}
	return sock;
}

int main (int argc, char **argv) 
{
	size_t l;
	int used = 0;
	int fd, res;
	char buf[1024];
	fd = sock_unix_connect("/var/run/yarrow.socket");
	if (fd <= 0) {
		perror("Sock unix connect");
		exit(1);
	}

	l = 64;
	res = 0;

	printf("sock_unix_connect sock %d\n", fd);

	sprintf(buf, "%u\r\n", l);

	res = write(fd, buf, strlen(buf)+1);
	if(res < 0) {
		perror("Write error");
		
	}

	
/*	res = poll(events,1,50000);
	if (res > 0) {
		printf("events fd %d \n", res);
	}
	else 
		perror("error of poll or timeout");
	
	printf("revents %d\n", events[0].revents);
*/
	l = l*2;
	printf("left %d\n", l);

	while (l) {
		res = read(fd, buf + used, l);	
		l -= res;
		used += res;
	}
	printf("Raed from server %d res %d buf: %s \n", strlen(buf), used, buf);
	monobit_test(buf, used);
	serial_test(buf,used);
	poker_test(buf, used);
	close(fd);

return 0;
}
