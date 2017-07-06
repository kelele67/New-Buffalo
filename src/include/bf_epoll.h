#include <sys/epoll.h>

#ifndef BF_EPOLL_H
#define BF_EPOLL_H

#define BF_EPOLL_READ 0
#define BF_EPOLL_WRITE 1
#define BF_EPOLL_RW 2
#define BF_EPOLL_

/* Epoll的timeout是3秒*/
#define BF_EPOLL_WAIT_TIMEOUT 3000

#define BF_EPOLL_BEHAVIOR_DEFAULT 2
#define BF_EPOLL_BEHAVIOR_TRIGGERED 3

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

typedef struct 
{
	int (*read) (int);
	int (*write) (int);
	int (*error) (int);
	int (*close) (int);
	int (*timeout) (int);	
} bf_epoll_handlers;

int bf_epoll_create(int max_events);
void *bf_epoll_init(int efd, bf_epoll_handlers * handler, int max_events);

bf_epoll_handlers *bf_epoll_set_handlers(void (*read) (int),
										 void (*write) (int),
										 void (*error) (int),
										 void (*close) (int),
										 void (*timeout) (int));

int bf_epoll_add(int efd, int fd, int mode, int behavior);
int bf_epoll_del(int efd, int fd);
int bf_epoll_change_mode(int efd, int fd, int mode);

#endif
