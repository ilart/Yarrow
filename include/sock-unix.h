/*
 * sock-unix.h
 */
#ifndef SOCK_UNIX_H_
#define SOCK_UNIX_H_

int sock_unix_connect(const char *path);
void sock_nonblock(int sock);
void sock_block(int sock);
int sock_unix_close(int sock);
int sock_unix_listen(const char *path);

#endif
