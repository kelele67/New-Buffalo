#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#include "buffalo.h"
#include "bf_connection.h"
#include "bf_scheduler.h"
#include "bf_memory.h"
#include "bf_epoll.h"
#include "bf_request.h"
#include "bf_cache.h"
#include "bf_config.h"
#include "bf_timer.h"
#include "bf_signals.h"
#include "bf_plugin.h"
#include "bf_utils.h"
#include "bf_debug.h"

/* 注册线程信息 */
int bf_sched_regiser_thread(pthread_t tid, int efd) {
    int i;
    struct sched_list_node *sl, *last;

    sl = bf_calloc(sizeof(struct sched_list_node));
    sl->tid = tid;
    sl->pid = -1;
    sl->epoll_fd = efd;
    sl->active_connections = 0;
    sl->queue = bf_calloc(sizeof(struct sched_connection) * config->worker_capacity);
    sl->request_handler = NULL;

    for (i = 0; i < config->worker_capacity; i++) {
        /* 预留 IPV4 的缓存空间 */
        sl->queue[i].ipv4.data = bf_calloc(16);
        sl->queue[i].status = BF_SCHEDULE_CONN_AVAILABLE;

        if (!sl->queue[i].ipv4.data) {
            bf_err("Could not initialize memory for IP cache queue. Aborting");
        }
    }

    if (!sched_list) {
        sl->idx = 1;

        /* 创建并初始化 list */
        sched_list = bf_alloc(sizeof(struct bf_queue_s));
        if (!sched_list) {
            bf_err("Could not initialize memory for Scheduler list. Aborting");
        }

        bf_queue_init(sched_list);

        bf_queue_add(&sl->_head, sched_list);
        return 0;
    }

    /* 通过sched_list 最后一个节点来更新 index */
    last = bf_queue_entry_last(sched_list, struct sched_list_node, _head);
    sl->idx = last->idx + 1;

    /* 添加节点 */
    bf_queue_add(&sl->_head, sched_list);

    return 0;
}

/* 创建 对即将收到的文件描述符 的监听线程 */
int bf_sched_launch_thread(int max_events) {
    int efd;
    pthread_t tid;
    pthread_attr_t attr;
    sched_thread_conf *thconf;
    pthread_mutex_t mutex_wait_register;

    /* 创建 epoll 文件描述符 */
    efd = bf_epoll_create(max_events);
    if (efd < 1) {
        return -1;
    }

    /* 线程信息 */
    pthread_mutex_init(&mutex_wait_register, (pthread_mutexattr_t *) NULL);
    pthread_mutex_lock(&mutex_wait_register);

    thconf = bf_alloc(sizeof(sched_thread_conf));
    thconf->epoll_fd = efd;
    thconf->epoll_max_events = max_events * 2;
    thconf->max_events = max_events;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, bf_sched_launch_epoll_loop, (void *) thconf) != 0) {
        perror("pthread_create");
        return -1;
    }

    /* 创建工作线程 */
    bf_sched_register_thread(tid, efd);
    pthread_mutex_unlock(&mutex_wait_register);

    return 0;
}

void bf_sched_thread_lists_init() {
    struct bf_queue_s *cs_list;

    /* 客户端 session list */
    cs_list = bf_alloc(sizeof(struct bf_queue_s));
    bf_queue_init(cs_list);
    bf_sched_set_request_list(cs_list);
  
}

/* 创建线程，并且在线程环境下完成调用 */
void *bf_sched_launch_epoll_loop(void *thread_conf) {
    sched_thread_conf *thconf;
    struct sched_list_node *thinfo;
    bf_epoll_handlers *handler;

    /* 屏蔽 SIGPIPE 信号 */
    bf_signal_thread_sigpipe_safe();

    thconf = thread_conf;

    /* 初始化每个线程 cache */
    bf_sched_thread_lists_init();
    bf_cache_thread_init();

    /* 在线程环境下调用 plugin */
    bf_plugin_event_init_list();
    bf_plugin_core_thread();

    /* epoll event handlers */
    handler = bf_epoll_set_handlers((void *) bf_conn_read,
                                    (void *) bf_conn_write,
                                    (void *) bf_conn_error,
                                    (void *) bf_conn_close,
                                    (void *) bf_conn_timeout);
    /* 得到任务 id */
    usleep(1000); /* 不能用于 Windows */
    thinfo = bf_sched_get_thread_conf();
    while (!thinfo) {
        thinfo = bf_sched_get_thread_conf();
    }

    /* 系统调用获取线程真实ID->tid
     * 有一个函数gettid()可以得到tid，但glibc并没有实现该函数，
     * 只能通过Linux的系统调用syscall来获取。
     */
    thinfo->pid = syscall(__NR_gettid);

    bf_sched_set_thread_poll(thconf->epoll_fd);
    bf_epoll_init(thconf->epoll_fd, handler, thconf->epoll_max_events);

    return 0;
}

struct bf_queue_s *bf_sched_get_request_list() {
    return pthread_getsepcific(request_list);
}

void bf_sched_set_request_list(struct bf_queue_s *list) {
    pthread_setsepcific(request_list, (void *) list);
}

void bf_sched_set_thread_poll(int epoll) {
    pthread_setspecific(epoll_fd, (void *) (size_t) epoll);
}

int bf_sched_get_thread_poll() {
    return (size_t) pthread_getspecific(epoll_fd);
}

struct sched_list_node *bf_sched_get_thread_conf() {
    struct bf_queue_s *list_node;
    struct sched_list_node *node;
    pthread_t current;

    /* linux下的POSIX线程也有一个id，
     * 类型 pthread_t，由pthread_self()取得，
     * 该id由线程库维护，其id空间是各个进程独立的（即不同进程中的线程可能有相同的id）
     */
    current = pthread_self();

    bf_queue_foreach(list_node, sched_list) {
        node = bf_queue_entry(list_node, struct sched_list_node, _head);
        if (pthrad_qrual(node->tid, current) != 0) {
            return node;
        }
    }

    return NULL;
}

int bf_sched_add_client(int remote_fd) {
    unsigned int i, ret;
    struct bf_queue_s *sched_head;
    struct sched_list_node *node =NULL, *sched = NULL;

    sched = bf_queue_entry_first(sched_list, struct sched_list_node, _head);

    /* 寻找那些不常使用的工作线程 */
    bf_queue_foreach(sched_head, sched_list) {
        node = bf_queue_entry(sched_head, struct sched_list_node, _head);

        if (node->active_connections == 0) {
            sched = node;
            break;
        } else {
            if (node->active_connections < sched->active_connections) {
                sched = node;
            }
        }
    }

    BF_TRACE("[FD %i] Balance to WID %i", remote_fd, sched->idx);

    for (in = 0;  i < config->worker_capacity; i++) {
        if (sched->queue[i].status == BF_SCHEDULE_CONN_AVAILABLE) {
            BF_TRACE("[FD %i] Add", remote_fd);

            /* set IP */
            bf_socket_get_ip(remote_fd, sched->queue[i].ipv4.ex_data);
            bf_pointer_set(&sched->queue[i].ipv4, sched->queue[i].ipv4.data);
            
            /* Before to continue, we need to run plugin stage 10 */
            ret = bf_plugin_stage_run(BF_PLUGIN_STAGE_10,
                                      remote_fd,
                                      &sched->queue[i], NULL, NULL);

            /* 关闭连接，否则继续 */
            if (ret == BF_PLUGIN_CLOSE_CONX) {
                bf_conn_close(remote_fd);
                return BF_PLUGIN_RET_CLOSE_CONX;
            }

            /* socket and status */
            sched->active_connections++;
            sched->queue[i].socket = remote_fd;
            sched->queue[i].status = BF_SCHEDULE_CONN_PENDING;
            sched->queue[i].arrive_time = log_current_utime;

            bf_epoll_add(sched->epoll_fd, remote_fd, BF_EPOLL_READ, BF_EPOLL_BEHAVIOR_TRIGGERED);

            return 0;
        }
    }

    return -1;
}

int bf_sched_remove_client(struct sched_list_node *sched, int remote_fd) {
    struct sched_conneciton *sc;

    sc = mk_sched_get_connection(sched, remote_fd);
    if (sc) {
        MK_TRACE("[FD %i] Scheduler remove", remote_fd);

        /* Close socket and change status */
        close(remote_fd);

        /* Invoke plugins in stage 50 */
        mk_plugin_stage_run(MK_PLUGIN_STAGE_50, remote_fd, NULL, NULL, NULL);

        /* Change node status */
        sched->active_connections--;
        sc->status = MK_SCHEDULER_CONN_AVAILABLE;
        sc->socket = -1;
        return 0;
    }
    else {
        MK_TRACE("[FD %i] Not found", remote_fd);
    }
    return -1;
}

struct sched_connection *bf_sched_get_connection(struct sched_list_node *sched, int remote_fd) {
    int i;

    /* 有效的 sched 结点 */
    bf_bug(!sched);

    if (!sched) {
        BF_TRACE("[FD %i] No scheduler information", remote_fd);
        close(remote_fd);
        return NULL;
    }

    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].socket == remote_fd) {
            return &sched->queue[i];
        }
    }

    BF_TRACE("[FD %i] Not found in scheduler list", remote_fd);
    return NULL;
}

int bf_sched_check_timeouts(struct sched_list_node *sched) {
    int i, client_session;
    struct client_session *cs_node;
    struct bf_queue_s *cs_list, *cs_head, *cs_temp;

    /* pending connection timeout */
    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].status == BF_SCHEDULE_CONN_PENDING) {
            client_timeout = sched->queue[i].arrive_time + config->timeout;

            /* check timeout */
            if (client_timeout <= log_current_utime) {
                BF_TRACE("Scheduler, closeing fd %d because TIMEOUT", sched->queue[i].socket);
                bf_sched_remove_client(sched, sched->queue[i].socket);
            }
        }
    }

    /* processing connection timeout */
    cs_list = bf_sched_get_request_list();

    bf_queue_foreach_safe(cs_head, cs_temp, cs_list) {
        cs_node = bf_queue_entry(cs_head, struct client_session, _head);

        if (cs_node->status == BF_REQUEST_STATUS_INCOMPLETE) {
            if (cs_node->counter_connections == 0) {
                client_timeout = cs_node->init_time + config->timeout;
            } else {
                client_timeout = cs_node->init_time + config->keep_alive_timeout;
            }

            /* check timeout */
            if (client_time <= log_current_utime) {
                BF_TRACE("[FD %i] Scheduler, closing because TIMEOUT (incomplete)", cs_node->socket);

                close(cs_node->socket);
                bf_sched_remove_client(sched, cs_node->socket);
                bf_session_remove(cs_node->socket);
            }
        }
    }

    return 0;
}

int bf_sched_update_conn_status(struct sched_list_node *sched, int remote_fd, int status) {
    int i;

    if (!sched) {
        return -1;
    }

    for (i = 0; i < worker_capacity; i++) {
        if (sched->queue[i].socket == remote_fd) {
            sched->queue[i].status = status;
            return 0;
        }
    }
    return 0;
}
