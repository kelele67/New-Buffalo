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

    
}