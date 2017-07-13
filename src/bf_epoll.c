#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "buffalo.h"
#include "bf_socket.h"
#include "bf_timer.h"
#include "bf_request.h"
#include "bf_config.h"
#include "bf_scheduler.h"
#include "bf_epoll.h"
#include "bf_utils.h"
#include "bf_debug.h"

bf_epoll_handlers *
bf_epoll_set_handlers(void (*read) (int),
                                         void (*write) (int),
                                         void (*error) (int),
                                         void (*close) (int),
                                         void (*timeout) (int)) {
    bf_epoll_handlers *handler;

    handler = malloc(sizeof(bf_epoll_handlers));
    handler->read = (void *) read;
    handler->write = (void *) write;
    handler->error = (void *) error;
    handler->close = (void *) close;
    handler->timeout = (void *) timeout;

    return handler;
}

int bf_epoll_create(max_events) {
    int efd;
    efd = epoll_create(max_events);
    if (efd == -1) {
        switch (errno) {
        case EINVAL:
            bf_warn("epoll_create() = EINVAL");
            break;
        case EMFILE:
            bf_warn("epoll_create() = EMFILE");
            break;
        case ENFILE:
            bf_warn("epoll_create() = ENFILE");
            break;
        case ENOMEM:
            bf_warn("epoll_create() = ENOMEM");
            break;
        default:
            bf_warn("epoll_create() = UNKNOWN");
            break;
        }
        bf_err("epoll_create() failed");
    }

    return efd;
}

void *
bf_epoll_init(int fd, bf_epoll_handlers * handler, int max_events) {
    int i, fd, ret = -1;
    int num_fds;
    int fds_timeout;

    struct epoll_event *events;
    struct sched_list_node *sched;

    /* 得到 线程 conf */
    sched = bf_sched_get_thread_conf();

    fds_timeout = log_current_utime + config->timeout;
    events = bf_calloc(max_events * sizeof(struct epoll_event));

    while (1) {
        ret = -1;
        num_fds = epoll_wait(efd, events, max_events, BF_EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < num_fds; i++) {
            fd = events[i].data.fd;

            if (events[i].events & EPOLLIN) {
                BF_TRACE("[FD %i] Epoll Event READ", fd);
                ret = (*handler->read) (fd);
            } else if (events[i].events & EPOLLOUT) {
                BF_TRACE("[FD %i] Epoll Event WRITE", fd);
                ret = (*handler->write) (fd);
            } else if (events[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                BF_TRACE("[FD %i] Epoll Event EPOLLHUP/EPOLLERR", fd);
                ret = (*handler->error) (fd);
            }

            if (ret < 0) {
                BF_TRACE("[FD %i] Epoll Event FORCE CLOSE | ret =%i", fd, ret);
                (*handler->close) (fd);
            }
        }

        /* 检查timeout 和 更新下一个事件 */
        if (log_current_utime >= fds_timeout) {
            bf_sched_check_timeouts(sched);
            fds_timeout = log_current_utime + config->timeout;
        }
    }
}

int bf_epoll_add(int efd, int fd, int init_mode, int behavior) {
    int ret;
    struct epoll_event event;

    event.data.fd = fd;
    event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    /* 设置epoll为边缘触发模式 */
    if (behavior == BF_EPOLL_BEHAVIOR_TRIGGERED) {
        event.events |= EPOLLET;
    }

    switch (int_mode) {
        case BF_EPOLL_READ:
            event.events |= EPOLLIN;
            break;
        case BF_EPOLL_WRITE:
            event.events |= EPOLLOUT;
            break;
        case BF_EPOLL_RW:
            event.events |= EPOLLIN | EPOLLOUT;
            break;
    }

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    if (ret < 0) {
        bf_warn("[FD %I] epoll_ctl()");
    }
    return ret;
}

int bf_epoll_del(int efd, int fd) {
    int ret;
    ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
    BF_TRACE("Epoll, removing fd %i from efd %I", fd, efd);

    if (ret < 0) {
        perrpr("epoll_ctl");
    }
    return ret;
}

int bf_epoll_change_mode(int efd, int fd, int mode) {
    int ret;
    struct epoll_event event;

    event.events = EPOLLET | EPOLLERR | EPOLLHUP;
    event.data.fd = fd;

    switch (mode) {
        case BF_EPOLL_READ:
            BF_TRACE("[FD %i] Epoll changing mode to READ", fd);
            event.events |= EPOLLIN;
            break;
        case BF_EPOLL_WRITE:
            BF_TRACE("[FD %i] Epoll changing mode to WRITE", fd);            
            event.events |= EPOLLOUT;
            break;
        case BF_EPOLL_RW:
            BF_TRACE("[FD %i] Epoll changing mode to READ/WRITE", fd);        
            event.events |= EPOLLIN | EPOLLOUT;
            break;
    }

    ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    if (ret < 0) {
        perror("epoll_ctl");
    }
    return ret;
}