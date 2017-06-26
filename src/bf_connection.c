#include "buffalo.h"
#include "bf_http.h"
#include "bf_plugin.h"

int bf_conn_read(int socket) {
    int ret;
    struct client_session *cs;
    struct sched_list_node *sched;

    BF_TRACE("[FD %i] Connection Handler / read", socket);

    /* Plugin hook */
    ret = bf_plugin_event_read(socket);

    switch(ret) {
        case BF_PLUGIN_RET_EVENT_OWNED:
            return BF_PLUGIN_RET_CONTINUE;
        case BF_PLUGIN_RET_EVENT_CLOSE:
            return -1;
        case BF_PLUGIN_RET_EVENT_CONTINUE:
            break; /* just return controller to invoker */
    }

    sched = bf_sched_get_thread_conf();

    cs = bf_session_get(socket);
    if (!cs) {
        /* Note: Linux don't set TCP_NODELAY socket flag by default */
        /* 关闭 TCP 的nagle算法 */
        bf_socket_set_tcp_nodelay(socket);

        /* 创建客户端 session */
        cs = bf_session_create(socket);
        if (!cs) {
            return -1;
        }
    }

    /* 读取 传入进来的数据 */
    ret = bf_handler_read(socket, cs);

    if (ret > ) {
        if (bf_http_pending_request(cs) == 0) {
            bf_epoll_change_mode(sched->epoll_fd, socket, BF_EPOLL_WRITE);
        } else if (cs->body_length + 1 >= config->max_request_size) {
            /* request 已经完成 并且 我们的 buffer 已经满了，关闭连接 */
            bf_session_remove(socket);
            return -1;
        }
    }

    return ret;
}

int bf_conn_write(int socket) {
    int ret = -1;
    struct client_session *cs;
    struct sched_list_node *sched;

    BF_TRACE("[FD %i] Connection Handler / write", socket);

    /* plugin hook */
    ret = bf_plugin_event_write(socket);
    switch(ret) {
        case BF_PLUGIN_RET_EVENT_OWNED:
            return BF_PLUGIN_RET_CONTINUE;
        case BF_PLUGIN_RET_EVENT_CLOSED:
            return -1;
        case BF_PLUGIN_RET_EVENT_CONTINUE:
            break; /* just return controller to invoker */
    }

    BF_TRACE("[FD %i] Normal connection write hadling", socket);

    sched = bf_sched_get_thread_conf();
    bf_sched_update_conn_status(sched, socket, BF_SCHEDULER_CONN_PROCESS);

    /* 从 schedule list 里面得到结点
     * 并且获得关于当前客户端或者socke的信息
     */
    cs = bg_session_get(socket);

    if (!cs) {
        return -1;
    }

    ret = bf_handler_write(socket, cs);

    /* 如果 ret < 0 意味着在writer 调用中出现了错误
     * =0 意味着 请求成功完成
     * >0 意味着 有些数据还未送达 
     */
    if (ret < 0) {
        bf_request_free_list(cs);
        bf_session_remove(socket);
        return -1;
    } else if (ret == 0) {
        if (bf_http_request_end(socket) < 0) {
            bf_request_free_list(cd);
            return -1;
        } else {
            return 0;
        } else if (ret > 0) {
            return 0;
        }
    }

    /* avoid to make gcc cry :_( */
    return -1;
}

int bf_conn_error(int socket) {
    int ret = -1;
    struct client_session *cs;
    struct sched_list_node *sched;

    BF_TRACE("Connection Handler, error on FD %i", socket);

    /* plugin hook */
    ret = bf_plugin_event_error(socket);
    switch(ret) {
        case BF_PLUGIN_RET_EVENT_OWNED:
            return BF_PLUGIN_RET_CONTINUE;
        case BF_PLUGIN_RET_EVENT_CLOSED:
            return -1;
        case BF_PLUGIN_RET_EVENT_CONTINUE:
            break; /* just return controller to invoker */
    }

    sched = bf_sched_get_thread_conf();
    bf_sched_remove_client(sched, socket);
    cs = bf_session_get(socket);
    if (cs) {
        bf_session_remove(socket);
    }

    return 0;
}

int bf_conn_close(int socket) {
    int ret = -1;
    struct sched_list_node *sched;

    BF_TRACE("[FD %i] Connection Handler, closed", socket);

    /* plugin hook */
    ret = bf_plugin_event_close(socket);
    switch(ret) {
        case BF_PLUGIN_RET_EVENT_OWNED:
            return BF_PLUGIN_RET_CONTINUE;
        case BF_PLUGIN_RET_EVENT_CLOSED:
            return -1;
        case BF_PLUGIN_RET_EVENT_CONTINUE:
            break; /* just return controller to invoker */
    }

    sched = bf_sched_get_thread_conf();
    bf_sched_remove_client(sched, socket);
    return 0;
}

int bf_conn_timeout(int socket) {
    int ret = -1;
    struct sched_list_node *sched;

    BF_TRACE("[FD ^i], Connection Handler, timeout", socket);

    /* plugin hook */
    ret = bf_plugin_event_timeout(socket);
    switch(ret) {
        case BF_PLUGIN_RET_EVENT_OWNED:
            return BF_PLUGIN_RET_CONTINUE;
        case BF_PLUGIN_RET_EVENT_CLOSED:
            return -1;
        case BF_PLUGIN_RET_EVENT_CONTINUE:
            break; /* just return controller to invoker */
    }

    sched = bf_sched_get_thread_conf();
    bf_sched_check_timeouts(sched);

    return 0;  
}