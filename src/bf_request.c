#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <time.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "bf_request.h"
#include "buffalo.h"
#include "bf_http.h"
#include "bf_http_status.h"
#include "bf_string.h"
#include "bf_config.h"
#include "bf_scheduler.h"
#include "bf_epoll.h"
#include "bf_utils.h"
#include "bf_header.h"
#include "bf_user.h"
#include "bf_method.h"
#include "bf_memory.h"
#include "bf_socket.h"
#include "bf_cache.h"
#include "bf_timer.h"
#include "bf_plugin.h"
#include "bf_debug.h"

/* 创建一个处理 request 数据的内存 */
static struct session_request *bf_request_alloc() {
    struct session_request *request = 0;

    request = bf_alloc(sizeof(struct session_request));
    request->status = BF_FALSE; /* Request not processed yet */
    request->close_now = BF_FALSE;

    bf_pointer_reset(&request->body);
    request->status = BF_TRUE;
    request->method = METHOD_NOT_FOUND;

    bf_pointer_reset(&request->uri);
    request->uri_processed.data = NULL;

    request->content_length = 0;
    request->content_type.data = NULL;
    request->connection.data = NULL;
    request->host.data = NULL;
    request->if_modified_since.data = NULL;
    request->last_modified.data = NULL;
    request->range.data = NULL;

    request->post_variables.data = NULL;
    bf_pointer_reset(&request->query_string);

    request->file_info = NULL;
    request->virtual_user = NULL;

    bf_pointer_reset(&request->real_path);
    request->host_conf = config->hosts;

    request->loop = 0;
    request->bytes_to_send = -1;
    request->bytes_offset = 0;
    request->fd_file = -1;

    /* response headers */
    reqeust->headers = bf_header_create();

    /* plugin handler */
    request->handle_by = NULL;

    /* 
     * FIXME: these fields will be dropped once plugins
     * uses the new headers ToC interface
     */
    request->accept.data = NULL;
    request->accept_language.data = NULL;
    request->accept_encoding.data = NULL;
    request->accept_charset.data = NULL;
    request->cookies.data = NULL;
    request->referer.data = NULL;
    request->resume.data = NULL;
    request->user_agent.data = NULL;

    return request;
}

static void bf_request_free(struct session_request *sr) {
    if (sr->fd_file > ) {
        close(sr->fd_file);
    }

    if (sr->headers) {
        bf_free(sr->headers->loaction);
        bf_free(sr->headers);
    }

    if (sr->uri_processed.data != sr->uri.data) {
        bf_pointer_free(&sr->uri_processed);
    }

    bf_pointer_reset(&sr->body);
    bf_pointer_reset(&sr->uri);
    bf_pointer_reset(&sr->query_string);

    bf_free(sr->file_info);
    bf_free(sr->virtual_user);

    bf_pointer_free(&sr->real_path);
    bf_free(sr);
}

static void bf_request_header_toc_parse(struct header_toc *toc, const char *data, int len) {
    char *p, *l = 0;
    int i;

    p = (char *)data;
    for (i = 0; i < BF_HEADERS_TOC_LEN && p && l < data + len; i++) {
        l = strstr(p, BF_CRLF);
        /* 如果有空行 */
        if (l) {
            toc[i].init = p;
            toc[i].end = l;
            p = l + bf_crlf.len;
        } else {
            break;
        }
    }
}

/* 返回一个在 request 里面发送的，其中包含 method, URI, protocol version,和所有
定义的static headers 的结构体 */
static int bf_request_header_process(struct session_request *sr) {
    int uri_init = 0, uri_end = 0;
    char *query_init = 0;
    int prot_init = 0, prot_end = 0, pos_sep = 0;
    int fh_limit = 0;
    char *port = 0;
    char *headers;
    char *temp = 0;
    bf_pointer host;

    /* method */
    sr->method_p = bf_http_method_check_str(sr-method);

    /* request uri */
    uri_init = (index(sr->body.data, ' ') - sr->body.data) + 1;
    fh_limit = (index(sr->body.data, '\n') - sr->body.data);

    uri_end = bf_string_char_search_r(sr->body.data, ' ', fh.limit) - 1;

    if (uri_end <= 0) {
        BF_TRACE("Error, first header bad formed");
        return -1;
    }

    prot_init = uri_end + 2;
    
    if (uri_end < uri_init) {
        return -1;
    }

    /* query string */
    query_init = index(sr->body.data + uri_init, '?');
    if (query_init) {
        int init, end;

        init = (int) (query_init - (sr->body.data + uri_init)) + uri_init;
        if (init <= uri_end) {
            end = uri_end;
            uri_end = init - 1;

            sr->query_string = bf_pointer_create(sr->body.data, init + 1, end + 1);
        } 
    }

    /* request uri part 2 */
    sr->uri = bf_pointer_create(sr->body.data, uri_init, uri_end + 1);

    if (sr->uri.len < 1) {
        return -1;
    }

    /* http version */
    prot_end = fh_limit - 1;
    if (prot_init == prot_end) {
        return -1;
    }

    if (prot_end != prot_init && prot_end > 0) {
        sr->protocol = bf_http_protocol_check(sr->body.data + prot_init, prot_end - prot_init);

        sr->protocol_p = bf_http_protocol_check_str(sr->protocol);
    }

    headers = sr->body.data + prot_end + bf_crlf.len;

    /* process URI, 如果包含 ASCII 字符 如 '%20'，
     * 就创建一个新的内存进行转码，如果不需要转码就返回
     * NULL
     */
    temp = bf_utils_url_decode(sr->uri);
    if (temp) {
        sr->uri_processed.data = temp;
        sr->uri_processed.len = strlen(temp);
    } else {
        sr->uri_processed.data = sr->uri.data;
        sr->uri_processed.len = sr->uri.len;
    }

    /* 为 HTTP headers 创建 Table of Content (index) */
    sr->headers_len = sr->body.len - (prot_end + bf_crlf.len);
    bf_reqquest_header_toc_init(sr->headers_toc);
    bf_reqquest_header_toc_parse(sr->headers_toc, headers, sr->headers_len);

    /* host */
    host = bf_request_header_get(sr->headers_toc, bf_rh_host);

    if (host.data) {
        if ((pos_sep = bf_string_char_search(host.data, ':', host.len)) >= 0) {
            /* just the host */
            sr->host.data = host.data;
            sr->host.len = host.len;

            /* including the port */
            sr->host_port = host;

            port = bf_string_copy_substr(host.data, pos_sep + 1, host.len);
            sr->port = strtol(port, (char **) NULL, 10);
            bf_free(port);
        } else {
            sr->host = host; /* maybe null */
            sr->port = config->standard_port;
        }
    } else {
        sr->host.data = NULL;
    }

    /* 寻找哪些 headers 是只有 buffalo 使用的 */
    sr->connection = bf_request_header_get(sr->headers_toc, bf_rh_connection);
    sr->range = bf_request_header_get(sr->headers_toc, bf_rh_range);
    sr->if_modified_since = bf_request_header_get(sr->headers_toc, bf_rh_if_modified_since);

    /* FIXME: this headers pointers should not be here, just keeping the reference
     * to avoid problems with Palm plugin
     */
    sr->accept = bf_request_header_get(sr->headers_toc, bf_rh_accept);
    sr->accept_charset = bf_request_header_get(sr->headers_toc, bf_rh_accept_charset);
    sr->accept_encoding = bf_request_header_get(sr->headers_toc, bf_rh_accept_encoding);

    sr->accept_language = bf_request_header_get(sr->headers_toc, bf_rh_accept_language);
    sr->cookies = bf_request_header_get(sr->headers_toc, bf_rh_cookie);

    /* 默认关闭 长连接 */
    if (sr->protocol == HTTP_PROTOCOL_10) {
        sr->keep_alive = BF_FALSE;
        sr->close_now = BF_TRUE;
    } else if (sr->protocol == HTTP_PROTOCOL_11) {
        sr->keep_alive = BF_TRUE;
        sr->close_now = BF_FALSE;
    }

    if (sr->connection.data) {
        if (bf_string_casestr(sr->connection.data, "Keep-Alive")) {
            sr->keep_alive = BF_FALSE;
            sr->close_now = BF_TRUE;
        } else {
            sr->connection.len = 0;
        }
    }

    return 0;
}

static int bf_request_parse(struct client_session *cs) {
    int i, end;
    int blocks = 0;
    struct session_request *sr_node;
    struct bf_queue_s *sr_list, *sr_head;

    for (i = 0; i <= cs->body_pos_end; i++) {
        /* Look for CRLFCRLF (\r\n\r\n), maybe some pipelining
         * request can be involved.
         */
        end = bf_string_search(cs->body + i, bf_endblock.data, BF_STRING_SENSITIVE) + i;

        if (end < 0) {
            return -1;
        }

        /*  创建 request 结点 */
        sr_node = bf_request_alloc();

        /* 用 bf_pointer指针 指向结点 */
        sr_node->body.data = cs->body + i;
        sr_node->body.len = end -i;

        /* Method, previous catch in bf_http_pending_request */
        if (i == 0) {
            sr_node->method = cs->first_method;
        } else {
            sr_node->method = bf_http_method_get(sr_node->body.data);
        }

        /* 找到 post 数据 */
        if (sr_node->method == HTTP_METHOD_POST) {
            int offset;
            offset = end + bf_endblock.len;
            sr_node->post_variables = bf_method_post_get_vars(cs->body + offset, cs->body_length - offset);

            if (sr_node->post_variables.len >= 0) {
                i += sr_node->post_variables.len;
            }
        }

        /* Increase index to the end of the current block */
        i= (end + bf_endblock.len)  - 1;

        /* link block */
        bf_queue_add(&sr_node->_head, &cs->request_list);

        /* update counter */
        blocks++;
    }

    /* 检查 pipelining connection */
    if (blocks > 1) {
        sr_list = &cs->request_list;
        bf_queue_foreach(sr_head, sr_list) {
            sr_node = bf_queue_entry(sr_head, struct session_request, _head);
            /* Pipelining request must use GET or HEAD methods */
            if (sr_node->method != HTTP_METHOD_GET &&
                sr_node->method != HTTP_METHOD_HEAD) {
                    return -1;
                }
        }
        cs->pipelined = BF_TRUE;
    }

    return 0;
}

/* This function allow the core to invoke the closing connection process
 * when some connection was not proceesed due to a premature close or similar
 * exception, it also take care of invoke the STAGE_40 and STAGE_50 plugins events
 */
static void bf_request_premature_close(int http_status, struct client_session *cs) {
    struct session_request *sr;
    struct bf_queue_s *sr_list = &cs->request_list;

    if (bf_queue_is_empty(sr_list)) == 0) {
        sr = bf_request_alloc();
        bf_queue_add(&sr->_head, &cs->request_list);
    } else {
        bf_queue_entry_first(sr_list, struct session_request, _head);
    }

    /* raise error */
    if (http_status > 0) {
        bf_request_error(http_status, cs, sr);

        /* STAGE_10, request has ended */
        bf_plugin_stage_run(BF_PLUGIN_STAGE_40, cs->socket, NULL, cs, sr);
    }

    /* STAGE_50, connection closed */
    bf_plugin_stage_run(BF_PLUGIN_STAGE_50, cs->socket, NULL, NULL, NULL);
    bf_session_remove(cs->socket);
}

static int bf_request_process(struct client_session *cs, struct session_request *sr) {
    int status = 0;
    struct host *host;

    status = bf_request_header_process(sr);
    if (status < 0) {
        bf_header_set_http_status(sr, BF_CLIENT_BAD_REQUEST);
        bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_ABORT;
    }

    switch(sr->method) {
        case METHOD_NOT_ALLOWED:
            bf_request_error(BF_CLIENT_METHOD_NOT_ALLOWED, cs, sr);
            return EXIT_NORMAL;
        case METHOD_NOT_FOUND:
            bf_request_error(BF_SERVER_NOT_IMPLEMENTED, cs, sr);
            return EXIT_NORMAL;
    }

    sr->user_home = BF_FALSE;

    /* uri 是否有效 */
    if (sr->uri_processed.data[0] != '/') {
        bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* HTTP/1.1 需要 host header */
    if (!sr->host.data && sr->protocol == HTTP_PROTOCOL_11) {
        bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* method 是否允许 */
    if (sr->method == METHOD_NOT_ALLOWED) {
        bf_request_error(BF_CLIENT_METHOD_NOT_ALLOWED, cs, sr);
        return EXIT_NORMAL;
    }

    /* 协议版本是否有效 */
    if (sr->protocol == HTTP_PROTOCOL_UNKOWN) {
        bf_request_error(BF_SERVER_HTTP_VERSION_UNSUP, cs, sr);
        return EXIT_ABORT;
    }

    if (sr->host.data) {
        host = bf_config_host_find(sr->host);
        if (host) {
            sr->host_conf = host;
        } else {
            sr->host_conf = config->hosts;
        }
    } else {
        sr->host_conf = config->hosts;
    }

    /* request 是否使用用户home主页目录 */
    if (config->user_dir &&
        sr->uri_processed.len > 2 &&
        sr->uri_processed.data[1] == BF_USER_HOME) {
            if (bf_user_init(cs, sr) != 0) {
                bf_request_error(BF_CLIENT_NOT_FOUND, cs, sr);
                return EXIT_ABORT;
                }
            }
    
    /* 处理 method request */
    if (sr->method == HTTP_METHOD_POST) {
        if ((status == bf_method_post(cs, sr)) == -1) {
            return status;
        }
    }

    /* 插件 stage 20 */
    int ret;
    ret = bf_plugin_stage_run(BF_PLUGIN_STAGE_20, cs->socket, NULL, cs, sr);

    if (ret == BF_PLUGIN_RET_CLOSE_CONX) {
        BF_TRACE("STAGE 20 request close connection");
        return EXIT_ABORT;
    }

    /* 正常 http 进程 */
    status = bf_http_init(cs, sr);

    BF_TRACE("[FD %i] HTTP init returning %i", cs->socket, status);
    return status;
}

/* 创建错误页面 */
static bf_pointer *bf_request_set_default_page(char *title, bf_pointer message, char *signature) {
    char *temp;
    bf_pointer *p;

    p = bf_alloc(sizeof(bf_pointer));
    p->data = NULL;

    temp = bf_pointer_to_buf(message);
    bf_string_build(&p->data, &p->len, BF_REQUEST_DEFAULT_PAGE, title, temp, signature);
    bf_free(temp);

    return p;
}

int bf_handler_read(int socket, struct client_session *cs) {
    int bytes;
    int pending = 0;
    int available = 0;
    int ret;
    int new_size;
    char *tmp = 0;

    /* 检查 read 的数量 */
    ret = ioctl(socket, FIONREAD, &pending);
    if (ret == -1) {
        bf_request_premature_close(BF_SERVER_INTERNAL_ERROR, cs);
        return -1;
    }

    /* 如果即将到来的数据没有足够的空间，重新分配buffer */
    if (pending > 0 && (pending >= (cs->body_size - (cs->body_length - 1)))) {
        /* 检查空间 */
        avaliable = (cs->body_size - cs->body_length) + BF_REQUEST_CHUNK;
        if (pending < avaliable) {
            new_size = cs->body_size + BF_REQUEST_CHUNK + 1;
        } else {
            new_size = cs->body.size + pending + 1;
        }

        if (new_size > config->max_request_size) {
            bf_request_premature_close(BF_CLIENT_REQUEST_TOO_LARGE, cs);
            return -1;
        }

        tmp = bf_realloc(cs->body, new_size);
        if (tmp) {
            cs->body = tmp;
            cs->body_size = new_size;
        } else {
            bf_request_premature_close(BF_SERVER_INTERNAL_ERROR, cs);
            return -1;
        }
    }

    /* 读取 内容 */
    bytes = bf_socket_read(socket, cs->body + cs->body_length, (cs->body_size - cs->body_length));

    if (bytes < 0) {
        if (errno == EAGAIN) {
            return 1;
        } else {
            bf_session_remove(socket);
            return -1;
        }
    }
    if (bytes == 0) {
        bf_session_remove(socket);
        return -1;
    }
    if (bytes >= 0) {
        cs->body_length += bytes;
        cs->body[cs->body_length] = '\0';
    }

    return bytes;
}

int bf_handler_write(int socket, struct client_session *cs) {
    int bytes, final_status = 0;
    struct session_request *sr_node;
    struct bf_queue_s *sr_list, *sr_head;

    /* 从 schedule list 中得到包含当前线程信息的 结点 */
    if (!cs) {
        return -1;
    }

    if (bf_queue_is_empty(&cs->request_list) == 0) {
        if (bf_request_parse(cs) != 0) {
            return -1;
        }
    }

    sr_list = &cs->request_list;
    bf_queue_foreach(sr_head, sr_list) {
        sr_node = bf_queue_entry(sr_head, struct session_request, _head);

        /* request 没有运行所以插件不运行 */
        if (sr_node->bytes_to_send < 0 && !sr_node->handle_by) {
            final_status = bf_request_process(cs, sr_node);
        }
        /* request 数据由静态文件发送 */
        else if (sr_node->bytes_to_send > 0 && !sr_node->handle_by) {
            final_status = bf_http_send_file(cs, sr_node);
        }

        /* 出现错误时，我们不解析并且发送信息给其他的 pipelined request */
        if (final_status > 0) {
            return final_status;
        }
        else if (final_status <= 0) {
            /* STAGE_40, request 被终止 */
            bf_plugin_stage_run(BF_PLUGIN_STAGE_40, cs->socket, NULL, cs, sr_node);
            switch(final_status) {
                case EXIT_NORMAL:
                case EXIT_ERROR:
                    if (sr_node->close_now == BF_TRUE) {
                        return -1;
                    }
                    break;
                case EXIT_ABORT:
                    return -1;
            }
        }
    }

    /* 如果运行到最后，说明所有管道上的request 都被成功运行了 */
    return 0;
}

/* 在路径文件中 查找是否有 index.xxx */
bf_pointer bf_request_index(char *pathfile) {
    unsigned long len;
    char *file_aux = NULL;
    bf_pointer f;
    struct bf_string_line *aux_index;

    bf_pointer_reset(&f);

    aux_index = config->index_files;

    while (aux_index) {
        bf_string_build(&file_aux, &len, "%s%s", pathfile, aux_index->val);

        if (access(file_aux, F_OK) == 0) {
            f.data = file_aux;
            f.len = len;
            return f;
        }
        bf_free(file_aux);
        file_aux = NULL;

        aux_index = aux_index->next;
    }

    return f;
}

/* 发送错误回复 */
void bf_request_error(int http_status, struct client_session *cs, struct session_request *sr) {
    char *aux_message = 0;
    bf_pointer message, *page = 0;
    long n;

    bf_pointer_reset(&message);

    switch(http_status) {
        case BF_CLIENT_BAD_REQUEST:
            page = bf_request_set_default_page("BAD REQUEST", sr->uri, sr->host_conf->host_signature);
            break;
        case BF_CLIENT_FORBIDDEN:
            page = bf_request_set_default_page("FORBIDDEN", sr->uri, sr->host_conf->host_signature);
            break;
        case BF_CLIENT_NOT_FOUND:
            bf_string_build(&message.data, &message.len, "The requested URL was not found on this server.");
            page = bf_request_set_default_page("NOT FOUND", message, sr->host_conf->host_signature);
            bf_pointer_free(&message);
            break;
        case BF_CLIENT_REQUEST_TOO_LARGE:
            bf_string_build(&message.data, &message.len, "The request entity is too large.");
            page = bf_request_set_default_page("ENTITY TOO LARGE", message, sr->host_conf->host_signature);
            bf_pointer_free(&message);
            break;
        case BF_CLIENT_MTEHOD_NOT_ALLOWED:
            page = bf_request_set_default_page("METHOD NOT ALLOWED", message, sr->host_conf->host_signature);
            break;
        
        case BF_CLIENT_REQUEST_TIMEOUT:
        case BF_CLIENT_LENGTH_REQUEST:
        break;

        case BF_SERVER_NOT_IMPLEMENTED:
            page = bf_request_set_default_page("METHOD NOT IMPLEMENTED", message, sr->host_conf->host_signature);
            break;
        case BF_SERVER_INTERNAL_ERROR:
            page = bf_request_set_default_page("INTERNAL SERVER ERROR", message, sr->host_conf->host_signature);
            break;
        case BF_SERVER_HTTP_VERSION_UNSUP:
            bf_pointer_reset(&message);
            page = bf_request_set_default_page("HTTP VERSION UNSUPPORTED", message, sr->host_conf->host_signature);
            break;
    }

    bf_header_set_http_status(sr, http_status);
    if (page) {
        sr->headers->content_length = page->len;
    }

    se->headers->location = NULL;
    sr->headers->cgi = SH_NOCGI;
    sr->headers->pconnecions_left = 0;
    sr->headers->last_modified = -1;

    if (aux_message) {
        bf_free(aux_message);
    }

    if (!page) {
        bf_pointer_reset(&sr->headers->content_type);
    } else {
        bf_pointer_set(&sr->headers->content_type, "text/html\r\n");
    }

    bf_header_send(cs->socket, cs, sr);

    if (page && sr->method != HTTP_METHOD_HEAD) {
        n = bf_socket_send(cs->socket, page->data, page->len);
        bf_pointer_free(page);
        bf_free(page);
    }

    /* 关闭 TCP_CORK 选项 */
    bf_socket_set_cork_flag(cs->socket, TCP_CORK_OFF);
}

void bf_request_free_list(struct client_session *cs) {
    struct session_request *sr_node;
    struct bf_queue_s *sr_head, *temp;

    /* sr = last node */
    BF_TRACE("[FD %i] Free struct client_session", cs->socket);

    bf_queue_foreach_safe(sr_head, temp, &cs->request_list) {
        sr_node = bf_queue_entry(sr_head, struct session_request, _head);
        bf_queue_del(sr_head);
        bf_request_free(sr_node);
    }
}

/* 创建一个client request 并且把它放进 主list中 */
struct client_session *bf_session_create(int socket) {
    struct client_session *cs;
    struct sched_connection *sc;
    struct sched_list_node *sched;
    struct bf_queue_s *cs_list;

    sched = bf_sched_get_thread_conf();
    sc = bf_sched_get_connection(sched, socket);
    if (!sc) {
        BF_TRACE("FAILED SOCKET: %i", socket);
        bf_warn("Sched connection not found");
        return NULL;
    }

    /* 为结点 分配内存 */
    cs = bf_alloc(sizeof(struct client_session));

    /* ipv4 address */
    cs->ipv4 = &sc->ipv4;

    cs->pipelined = BF_FALSE;
    cs->counter_connections = 0;
    cs->socket = socket;
    cs->status = BF_REQUEST_STATUS_INCOMPLETE;

    /* UNIX time */
    cs->init_time = sc->arrive_time;

    /* 为消息主体 分配内存 */
    cs-body = bf_alloc(BF_REQUEST_CHUNK);

    cs->body_size = BF_REQUEST_CHUNK;
    cs->body_length = 0;

    cs->body_pos_end = -1;
    cs->first_method = HTTP_METHOD_UNKNOWN;

    /* 初始化 session request list */
    bf_queue_init(&cs->request_list);

    /* 添加 session 到 线程list */
    cs_list = bf_sched_get_request_list();

    /* 添加 结点 到 list */
    bf_queue_add(&cs->_head, cs_list);

    /* 重新建立 全局 list */
    bf_sched_set_request_list(cs_list);

    return cs;
}

struct client_session *bf_seesion_get(int socket) {
    struct client_session *cs_node = NULL;
    struct bf_queue_s *cs_list, *cs_head;

    cs_list = bf_sched_get_request_list();
    bf_queue_foreach(cs_head, cs_list) {
        cs_node = bf_queue_entry(cs_head, struct client_session, _head);
        if (cs_node->socket == socket) {
            return cs_node;
        }
    }

    return NULL;
}

/* 把client_session 信息从线程的 sched_list_node list 中 移除 */
void bf_session_remove(int socket) {
    struct client_session *cs_node;
    struct bf_queue_s *cs_list, *cs_head, *temp;

    cs_list = bf_sched_get_request_list();

    bf_queue_foreach_safe(cs_head, temp, cs_list) {
        cs_node = bf_queue_entry(cs_head, struct client_session, _head);
        if (cs_node->socket == socket) {
            bf_queue_del(cs_head);
            bf_free(cs_node->body);
            bf_free(cd_node);
            break;
        }
    }

    /* 更新 线程 index */
    bf_sched_get_request_list(cs_list);
}

void bf_reqeust_header_toc_init(struct header_toc *toc) {
    int i;
    for (i = 0; i < BF_HEADERS_TOC_LEN; i++) {
        toc[i].init = NULL;
        toc[i].end = NULL;
        toc[i].status = 0;
    }
}

bf_pointer bf_request_header_get(struct header_toc *toc, bf_pointer header) {
    int i;
    bf_pointer var;

    var.data = NULL;
    var.len = 0;

    if (toc) {
        for (i = 0; i < BF_HEADERS_TOC_LEN; i++) {
            /* status = 1 意味着 toc entry入口准备好了 */
            if (toc[i].status == 1) {
                continue;
            }

            if (!toc[i].init) {
                break;
            }

            if (strcasecmp(toc[i].init, header.data, header.len) == 0) {
                var.data = toc[i].init + header.len + 1;
                var.len = toc[i].end - var.data;
                toc[i].status = 1;
                return var;
            }
        }
    }

    return var;
}

void bf_reqeust_ka_next(struct client_session *cs) {
    memset(cs->body, '\0', sizeof(cs->body));
    cs->first_method = -1;
    cs->body_pos_end = -1;
    cs->body_length = 0;
    cs->counter_connections++;

    /* 更新调度 数据 */
    cs->init_time = log_current_time;
    cs->status = BF_REQUEST_STATUS_INCOMPLETE;
}