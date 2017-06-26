#ifndef BF_BUFFALO_H
#define BF_BUFFALO_H

#include <pthread.h>
#include <netinet/in.h>
#include "bf_memory.h"

int server_fd;

/* 最大路径长度 */
#define MAX_PATH 1024

/* Send_Header(..., int cgi) */
#define SH_NOCGI 0
#define SH_CGI 1

/* 线程锁 */
pthread_mutex_t mutex_wait_register;
/* 互斥锁属性的协议 */
bf_pointer bf_buffalo_protocol;
bf_pointer bf_buffalo_port;

/* 进程的所有者权限UID和目录权限GID */
gid_t EUID;
gid_t EGID;

#endif
