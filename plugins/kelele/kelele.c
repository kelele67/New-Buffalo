#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#include "BFPlugin.h"

BUFFALO_PLUGIN("kelele", 		 	  // shortname
			   "Kelele Network", 	  // name
			   VERSION, 		 	  // version
			   BF_PLUGIN_NETWORK_IO); // hooks

struct bf_config *conf;

int _bfp_init(void **api, char *confdir) {
	bf_api = *api;
	return 0;
}

void _bfp_exit() {

}

int _bfp_network_io_accept(int server_fd, struct sockaddr_in sock_addr) {
	int remote_fd;
	socklen_t socket_size = sizeof(struct sockaddr_in);

#ifdef ACCEPT_GENERIC
	remote_fd = accept(server_fd, (struct sockaddr *) &sock_addr, &socket_size);

	if (fcntl(server_fd, F_SETFL, fcntl(remote_fd, F_GETFD, 0) | O_NONBLOCK) == -1) {
		bf_err("Cannot set to non-blocking the socket");
		bf_err("Cannot set to non-blocking the socket");
	}
#else
	remote_fd = accept4(server_fd, (struct sockaddr *) &sock_addr, &socket_size, SOCK_NONBLICK);

#endif

	return remote_fd;
}

int _bfp_network_io_read(int socket_fd, void *buf, int count) {
	ssize_t bytes_read;
	bytes_read = read(socket_fd, (void *)buf, count);
	return bytes_read;
}

int _bfp_network_io_write(int socket_fd, const void *buf, size_t count) {
	ssize_t bytes_send = -1;
	bytes_send = write(socket_fd, buf, count);
	return bytes_send;
}

int _bfp_network_io_writev(int socket_fd, struct bf_iov *bf_io) {
	ssize_t bytes_sent = -1;
	bytes_sent = bf_api->iov_send(socket_fd, bf_io);
	return bytes_sent;
}

int _bfp_network_io_close(int socket_fd) {
	close(socket_fd);
	return 0;
}

int _bfp_network_io_connect(int socket_fd, char *host, int port) {
	int res;
	struct sockaddr_in *remote;

	remote = (struct sockaddr_in *) bf_api->bf_calloc(sizeof(struct sockaddr_in));
	remote->sin_family = AF_INET;

	res = inet_pton(AF_INET, host, (void *) (&(remote->sin_addr.s_addr)));

	if (res < 0) {
		bf_warn("Cannot set remote->sin_addr.s_addr");
		bf_api->bf_free(remote);
		return -1;
	}

	remote->sin_port = htons(port);
	if (connect(socket_fd, (struct sockaddr *) remote, sizeof(struct sockaddr)) == -1) {
		close(socket_fd);
		bf_err("connect");
		return -1;
	}

	bf_api->bf_free(remote);

	return 0;
}

int _bfp_network_io_send_file(int socket_fd, int file_fd, off_t *file_offset, size_t file_count) {
	ssize_t bytes_written = -1;
	bytes_written = sendfile(socket_fd, file_fd, file_offset, file_count);

	if (bytes_written == -1) {
		bf_warn("error from sendfile()");
		return -1;
	}

	return bytes_written;
}

int _bfp_network_io_create_socket(int domain, int type, int protocol) {
	int socket_fd;
	socket_fd = socket(domain, type, protocol);
	return socket_fd;
}

int _bfp_network_io_bind(int socket_fd, const struct sockaddr *addr, socklen_t addrlen, int backlog) {
	int ret;
	ret = bind(socket_fd, addr, addrlen);

	if (ret == -1) {
		bf_warn("Error binding socket");
		return ret;
	}
	ret = listen(socket_fd, backlog);

	if (ret == -1) {
		bf_warn("Error setting up the listener");
		return -1;
	}

	return ret;
}

int _bfp_network_io_server(int port, char *listen_addr) {
	int socket_fd;
	int ret;
	struct sockaddr_in local_sockaddr_in;

	socket_fd = _bfp_network_io_create_socket(PF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		bf_warn("Error creating server socket");
		return -1;
	}
	bf_api->socket_set_tcp_nodelay(socket_fd);

	local_sockaddr_in.sin_family = AF_INET;
	local_sockaddr_in.sin_port = htons(port);
	inet_pton(AF_INET, listen_addr, &local_sockaddr_in.sin_addr.s_addr);
	memset(&(local_sockaddr_in.sin_zero), '\0', 8);

	bf_api->socket_reset(socket_fd);

	ret = _bfp_network_io_bind(socket_fd, (struct sockaddr *) &local_sockaddr_in, 
							   sizeof(struct sockaddr), bf_api->sys_get_somaxconn());

	if (ret == -1) {
		bf_err("Port %i cannot be used\n", port);
		return -1;
	}

	return socket_fd;
}