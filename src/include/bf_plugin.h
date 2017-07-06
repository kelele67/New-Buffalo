#include "buffalo.h"
#include "include/bf_config.h"
#include "include/bf_request.h"
#include "include/bf_memory.h"
#include "include/bf_iov.h"
#include "include/bf_socket.h"
#include "include/bf_epoll.h"
#include "include/bf_header.h"
#include "include/bf_http_status.h"
#include "include/bf_utils.h"
#include "include/bf_striing.h"
#include "include/bf_queue.h"
#include "include/bf_info.h"

#ifndef BF_PLUGIN_H
#define BF_PLUGIN_H

#define BF_PLUGIN_LOAD "plugins.load"

#define MK_PLUGIN_ERROR -1      /* 插件运行错误 */
#define MK_PLUGIN_

/* 插件 核心类型 */
#define MK_PLUGIN_CORE_PRCTX (1)
#define MK_PLUGIN_CORE_THCTX (2)

/* 插件 阶段 */
#define MK_PLUGIN_STAGE_10 (4)    /* accept()连接刚刚建立 */
#define MK_PLUGIN_STAGE_20 (8)    /* HTTP Request 到达 */
#define MK_PLUGIN_STAGE_30 (16)   /* 对象 handler  */
#define MK_PLUGIN_STAGE_40 (32)   /* content 内容完成 */
#define MK_PLUGIN_STAGE_50 (64)   /* connection 连接终止 */

/* 插件 网络类型 */
#define MK_PLUGIN_NETWORK_IO (128)
#define MK_PLUGIN_NETWORK_IP (256)

/* 返回值 */
#define MK_PLUGIN_RET_NOT_ME -1
#define MK_PLUGIN_RET_CONTINUE 100
#define MK_PLUGIN_RET_END 200
#define MK_PLUGIN_RET_CLOSE_CONX 300

/* 事件返回值
 * 
 * 每个插件都可以 hook 任意一个 socket event 
 * 当一个工作线程通过epoll收到一个 socket event 时
 * 在由 buffalo core 控制之前
 * 首先检查第一个hook的插件
 */

/* 插件要求调用者继续下一个插件调用 */
#define BF_PLUGIN_RET_EVENT_NEXT -300

/* 插件已经完成，并且没有其他插件hook在这个event上，尽快返回 */
#define BF_PLUGIN_RET_EVENT_OWNED -400

/* 插件请求完成 session request */
#define BF_PLUGIN_RET_EVENT_CLOSE -500

/* 插件要求调用者跳过事件 hook */
#define BF_PLUGIN_RET_EVENT_CONTINUE -600

/* 进程/线程 环境 */
struct plugin_core {
    int (*prctx) ();
    int (thctx) ();
};

struct plugin_stage {
    int (*s10) (int, struct sched_connection *);
    int (*s20) (struct client_session *, struct session_request *);
    int (*s30) (struct plugin *, struct client_session *, struct session_request *);
    int (*s40) (struct client_session *, struct session_request *);
    int (*s50) (int);
};

struct plugin_network_io {
    int (*accept) (int, struct sockaddr_in);
    int (*read) (int, void *, int);
    int (*write) (int, const coid *, size_t);
    int (*close) (int);
    int (*connect) (int, char *, int);
    int (*send_file) (int, int, off_t *, size_t);
    int (*create_socket) (int, int, int);
    int (*bind) (int, const struct sockaddr *addr, socklen_t, int);
    int (*server) (int, char *);
};

struct plugin_network_ip {
    int (*addr) (int);
    int (*maxlen) ();
};

struct plugin {
    char *shortname;
    char *name;
    char *version;
    char *path;
    void *handler;
    unsigned int hooks;

    // 强制转换
    int (*init) (void *, char *);
    int (*exit) ();

    // hooks
    struct plugin_core core;
    struct plugin_stage stage;
    struct plugin_network_io net_io;

    // epoll 事件
    int (*event_read) (int);
    int (*event_write) (int);
    int (*event_error) (int);
    int (*event_close) (int);
    int (*event_timeout) (int);

    // 每个插件在全局数据里面都有一个 线程参数
    pthread_key_t *thread_key;

    struct bf_queue_s _head;
};

/**
 * 不同的插件可以有不同的状态，
 * 这里我们建立一个表来直接调用不同状态，
 * 为了避免服务器每次都要比较每个插件去寻找一个特定的插件
 */
struct plugin_stagem {
    struct plugin *p;
    struct plugin_stagem *next;
};

struct plugin_stagemap {
    struct plugin_stagem *stage_10; // 服务器尚未进入循环，尚未建立监听
    struct plugin_stagem *stage_15; 
    struct plugin_stagem *stage_20; // 接收连接但是还没有建立工作线程
    struct plugin_stagem *stage_30; // 接收到HTTP请求
    struct plugin_stagem *stage_40; // 对象handler
    struct plugin_stagem *stage_50; // 请求完毕
};

struct plugin_stagemap *plg_stagemap;

// 插件的api接口
struct plugin_api {
    struct server_config *config;
    struct bf_queue_s *plugins;
    struct bf_queue_s **sched_list;

    // error
    int *(*_error) (int, const char ...);

    // HTTP 请求
    int *(*http_request_end) (int);

    // 内存
    void *(*bf_lloc) (int);
    void *(*bf_alloc) (int);
    void (*bf_free) (void*);
    void (*pointer_set) (bf_pointer *, char *);
    void (*pointer_print) (bf_pointer);
    char *(*pointer_to_buf) (bf_pointer);

    // string
    int (*str_itop) (int, bf_pointer *);
    int (*str_search) (const char *, const char *, int);
    int (*str_search_n) (const char *, const char *, int, int);
    char *(*str_build) (char **, unsigned long *, const char *, ...);
    char *(*str_dup) (const char *);
    char *(*str_copy_substr) (const char *, int, int);
    struct bf_string_line *(*str_split_line) (const char *);

    // file
    char *(*file_to_buffer) (char *);
    struct file_info *(*file_get_info) (char *);

    // header
    int (*header_send) (int, struct client_session *, struct session_request *);
    bf_pointer (*header_get) (struct header_toc *, bf_pointer);
    int (*header_add) (struct session_request *, char *row, int len);
    void (*header_set_http_status) (struct session_request *, int);

    // iov
    struct bf_iov *(*iov_create) (int, int);
    void (*iov_free) (struct bf_iov *);
    int (*iov_add_entry) (struct bf_iov *, char *, int, bf_pointer, int);
    int (*iov_set_entry) (struct bf_iov *, char *, int, int, int);
    ssize_t (*iov_send) (int, struct bf_iov *);
    void (*iov_print) (struct bf_iov *);

    // plugin
    void *(*plugin_load_symbol) (void *, char *);

    // epoll
    void *(*epoll_init) (int, bf_epoll_handlers *, int);
    int (*epoll_create) (int);
    int (*epoll_add) (int, int, int, int);
    int (*epoll_del) (int, int);
    int (*epoll_change_mode) (int, int, int);

    // socket
    int (*socket_cork_flag) (int, int);
    int (*socket_reset) (int);
    int (*socket_set_tcp_nodelay) (int);
    int (*socket_connect) (int);
    int (*socket_set_noblocking) (int);
    int (*socket_create) ();
    int (*socket_close) (int);
    int (*socket_sendv) (int, struct bf_iov *);
    int (*socket_send) (int, const void *, size_t);
    int (*socket_read) (int, void *, int);
    int (*socket_send_file) (int, int, off_t, size_t);

    // config
    struct bf_config *(*config_create) (char *);
    void (*config_free) (struct bf_config *);
    struct bf_config_section *(*config_section_get) (struct bf_config *, char *);
    void *(*config_section_getval) (struct bf_config_section *, char *, int);

    //scheduler
    int (*shced_remove_session) (int);
    struct sched_connection *(*sched_get_connection) (struct sched_list_node *, int);

    // worker
    int (*worker_spawn) (void (*func) (void *));

    

    // epoll_event
    // int (*event_read) (int);
    // int (*event_write) (int);
    // int (*event_error) (int);
    // int (*event_close) (int);
    // int (*event_timeout) (int);
    int (*event_add) (int, int, struct plugin *, struct client_session *, struct session_request *);
    int (*event_del) (int);
    int (*event_socket_change_mode) (int, int);

    // system
    int (*sys_get_somaxconn) ();

    // utils
    int (*time_unix) ();
    bf_pointer *(*time_human)();

    #ifdef TRACE
        void (*trace) ();
        int (*errno_print) (int);
    #endif

};