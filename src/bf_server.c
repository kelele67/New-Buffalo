#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "buffalo.h"
#include "bf_config.h"
#include "bf_scheduler.h"
#include "bf_epoll.h"
#include "bf_socket.h"
#include "bf_plugin.h"
#include "bf_utils.h"
#include "bf_debug.h"

/* 返回能够承受的客户端最大数和同时的每个工作线程容量 */
int bf_server_worker_capacity(int nworkders) {
    int max, avl;
    struct rlimit limit;

    /* 系统限制 */
    /* 获得每个进程能够创建的各种系统资源的限制使用量 */
    getrlimit(RLIMIT_NOFILE, &limit); /* 每个进程能打开的最多文件数 */
    max = limit.rlim_cur;  /* 当前（软）限制 */

    /* Buffalo 中每个 fds 需要的最小值 :
     * --------------------------------
     * 3 fds: stdin, stdout, stderr
     * 1 fd: main socket server
     * 1 fd: epoll array (per thread)
     * 1 fd: worker logger when writing to FS
     * 2 fd: worker logger pipe
     */

     avl = max - (3 + 1 + nworkders + 1 + 2);
    /* avl 除以 2 是因为我们需要考虑到在同一个请求中
     * 可能每个运行中的插件可能有额外的FD
     */
     return ((avl / 2) / nworkders);
}

/* 建立新的 worker thread 去连接客户端 */
void bf_server_launch_workers() {
    int i;

    /* 建立 wokers */
    for (i = 0; i < config->workers; i++) {
        bf_sched_launch_thread(config->worker_capacity);
    }
}

void bf_server_loop(int server_fd) {
    int remote_fd;
    struct sockaddr_in sockaddr;

    bf_info("HTTP Server Started");

    for ( ; ; ) {
        remote_fd = bf_socket_accept(server_fd, sockaddr);

        if (remote_fd == -1) {
            continue;
        }

#ifdef TRACE
        BF_TRACE("New connrction arrived: FD %i", remote_fd);

        struct bf_queue_s *sched_head;
        struct sched_list_node *node;

        BF_TRACE("Worker Status");
        bf_queue_foreach(sched_head, sched_list) {
            node = bf_queue_entry(sched_head, strcuct sched_list_node, _head);
            BF_TRACE(" SID %i / conx = %i", node->index, node->active_connections);
        }
#endif

        /* 给 worker thread 分配一个 socket */
        bf_sched_add_client(remote_fd);
    }
}