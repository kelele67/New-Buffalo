#ifndef BF_SCHEDULE_H
#define BF_SCHEDULE_H

#include "include/bf_queue.h"
#include <pthread.h>

#define BF_SCHEDULE_CONN_AVAILABLE  -1
#define BF_SCHEDULE_CONN_PENDING 0
#define BF_SCHEDULE_CONN_PROCESS 1

struct sched_connection {
    int socket;
    int status;
    bf_pointer ipv4;
    time_t arrive_time;
};

/* 全局结构 */
struct sched_list_node {
    short int idx;
    pthread_t tid;
    pid_t pid;
    int epoll_fd;
    unsigned int active_connections;

    struct sched_connection *queue;
    struct client_session *request_handler;

    struct bf_queue_s _head;
};

struct bf_queue_s *sched_list;

/* 线程环境下的结构 */
typedef struct {
    int epoll_fd;
    int epoll_max_events;
    int max_events;
} sched_thread_conf;

pthread_key_t epoll_fd;

int bf_sched_register_thread(pthread_t tid, int epoll_fd);
int bf_sched_launch_thread(int max_events);
void *bf_sched_launch_epoll_loop(void *thread_conf);
struct sched_list_node *bf_sched_get_handler_owner(void);

struct bf_queue_s *bf_sched_get_request_list(void);
void bf_sched_set_request_list(struct bf_queue_s *list);

int bf_sched_get_thread_poll(void);
void bf_sched_set_thread_poll(int epoll);

struct sched_list_node *bf_sched_get_thread_conf(void);
void bf_shced_update_thread_status(struct sched_list_node *sched, int active, int closed);

int bf_sched_check_timeouts(struct sched_list_node *sched);
int bf_sched_add_client(int remote_fd);
int bf_sched_remove_client(struct sched_list_node *sched, int remote_fd);
struct sched_connection *bf_shced_get_connection(struct sched_list_node *sched, int remote_fd);
int bf_sched_update_conn_status(struct sched_list_node *sched, int remote_fd, int status);

#endif