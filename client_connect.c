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

char packet[128];

int
request_send(const char *buf)
{
	int len;

//	assert(sizeof(packet) > sizeof(buf));
	len = strlen(buf);
	strncpy(packet, buf, len);
	
	packet[len] = '\r';
	packet[len + 1] = '\n';
	packet[len + 2] = '\0';

	printf("Packet will send: \"%s\" \n", packet);
	return 0;
}

int main (int argc, char **argv) 
{
	int i, fd, res;
	char buf[128];
	fd = sock_unix_connect("/var/run/yarrow.socket");
	if (fd <= 0) {
		perror("Sock unix connect");
		exit(1);
	}

	printf("sock_unix_connect sock %d\n", fd);

	sprintf(buf, "%d", 130);
	res = request_send(buf);

	res = write(fd, packet, strlen(packet)+1);
	if(res < 0) {
		perror("Write error");
		
	}

	printf("Bytes was write %d, packet %s\n", res, packet);
	
/*	res = poll(events,1,50000);
	if (res > 0) {
		printf("events fd %d \n", res);
	}
	else 
		perror("error of poll or timeout");
	
	printf("revents %d\n", events[0].revents);
*/	
	do {
		res = read(fd, buf, sizeof(buf));	
	} while (res == 0);
	
	printf("Raed from server buf: \"%s\" \n", buf);


	close(fd);
return 0;
}
