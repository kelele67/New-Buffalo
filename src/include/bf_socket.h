#ifndef BF_SOCKET_H
#define BF_SOCKET_H

#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "bf_iov.h"
#include "bf_request.h"

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif

/* Socket_Timeout() */
#define ST_RECV 0
#define ST_SEND 1

#define TCP_CORK_ON 1
#define TCP_CORK_OFF 0


int bf_socket_set_cork_flag(int fd, int state);
int bf_socket_set_tcp_nodelay(int sockfd);
int bf_socket_set_nonblocking(int sockfd);

int bf_socket_get_ip(int socket, char *ipv4);
int bf_socket_close(int socket);
int bf_socket_timeout(int s, char *buf, int len, int timeout, int recv_send);

int bf_socket_create(void);
int bf_socket_connect(int socket_fd, char *host, int port);
int bf_socket_reset(int socket);
int bf_socket_server(int port, char *listen_addr);

int bf_socket_accept(int server_fd, struct sockaddr_in sock_addr);
int bf_socket_sendv(int socket_fd, struct bf_iov *bf_io);
int bf_socket_send(int socket_fd, const void *buf, size_t count);
int bf_socket_read(int socket_fd, void *buf, int count);
int bf_socket_send_file(int socket_fd, int file_fd, off_t *file_offset, size_t file_count);

#endif