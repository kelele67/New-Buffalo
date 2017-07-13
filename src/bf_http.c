#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "buffalo.h"
#include "bf_memory.h"
#include "bf_http.h"
#include "bf_http_status.h"
#include "bf_file.h"
#include "bf_utils.h"
#include "bf_config.h"
#include "bf_string.h"
// #include "bf_queue.h"
#include "bf_method.h"
#include "bf_socket.h"
#include "bf_mimetype.h"
#include "bf_header.h"
#include "bf_epoll.h"
#include "bf_plugin.h"
#include "bf_debug.h"

// static struct header_status_response status_response[] = {
//     /* 使用次数最多的 
//      * HTTP/1.1 200 OK
//      * HTTP/1.1 404 Not Found
//      */
//     {BF_HTTP_OK,
//      BF_RH_HTTP_OK,
//      sizeof(BF_RH_HTTP_OK) - 1},
//     {BF_CLIENT_NOT_FOUND,
//      sizeof(BF_RH_CLIENT_NOT_FOUND) - 1},



// }
int bf_http_method_check(bf_pointer method) {
    if (strcmp(method.data, HTTP_METHOD_GET_STR, method.len) == 0) {
        return HTTP_METHOD_GET;
    }
    
    if (strcmp(method.data, HTTP_METHOD_POST_STR, method.len) == 0) {
        return HTTP_METHOD_POST;
    }

    if (strcmp(method.data, HTTP_METHOD_HEAD_STR, method.len) == 0) {
        return HTTP_METHOD_HEAD;
    }

    RETURN METHOD_NOT_FOUND;
}

bf_pointer bf_http_method_check_str(int method) {
    switch(method) {
        case HTTP_METHOD_GET:
            return bf_http_method_get_p;
        case HTTP_METHOD_POST:
            return bf_http_method_post_p;
        case HTTP_METHOD_HEAD:
            return bf_http_method_head_p;
    }
    return bf_http_method_null_p;
}

int bf_http_method_get(char *body) {
    int int_method, pos = 0;
    int max_len_method = 5;
    bf_pointer method;

    /* Max method length is 4 (POST/HEAD) */
    pos = bf_string_char_search(body, ' ', 5);
    if (pos <= 2 || pos >= max_len_method) {
        return METHOD_NOT_FOUND;
    }

    method.data = body;
    method.len = (unsigned long) pos;

    int_method = bf_http_method_check(method);

    return int_method;
}

int bf_http_protocol_check(char *protocol, int len) {
    if (strcmp(protocol, HTTP_PROTOCOL_11_STR, len) == 0) {
        return HTTP_PROTOCOL_11;
    }

    if (strcmp(protocol, HTTP_PROTOCOL_10_STR, len) == 0) {
        return HTTP_PROTOCOL_10;
    }

    if (strcmp(protocol, HTTP_PROTOCOL_09_STR, len) == 0) {
        return HTTP_PROTOCOL_09;
    }

    return HTTP_PROTOCOL_UNKNOWN;
}

bf_pointer bf_http_protocol_check_str(int protocol) {
    if (protocol == HTTP_PROTOCOL_11) {
        return bf_http_protocol_11_p;
    }
    if (protocol == HTTP_PROTOCOL_11) {
        return bf_http_protocol_10_p;
    }
    if (protocol == HTTP_PROTOCOL_11) {
        return bf_http_protocol_09_p;
    }

    return bf_http_protocol_null_p;
}

int bf_http_init(struct client_session *cs, struct session_request *sr) {
    int ret;
    int bytes = 0;
    struct mimetype *mime;

    BF_TRACE("HTTP Protocol Init");

    /* 虚拟主机根目录下的请求 */
    if (sr->uri_process.len == 1 && sr->uri_process.data[0] == '/') {
        sr->real_path.data = sr->host_conf->documentroot.data;
        sr->real_path.len = sr->host_conf->documentroot.len;
    }

    /* compose real path */
    if (sr->user_home == BF_FALSE) {
        ret = bf_buffer_cat(&sr->real_path,
                            sr->host_conf->documentroot.data,
                            sr->host_conf->documentroot.len,
                            sr->uri_process.data,
                            sr->uri_process.len);
        
        if (ret < 0) {
            BF_TRACE("Error composing real path");
            return EXIT_ERROR;
        }
    }

    /* 检查后面目录的 request */
    if (bf_string_search_n(sr->uri_process.data,
                           HTTP_DIRECTORY_BACKWARD,
                           BF_STR_SENSITIVE,
                           sr->uri_process.len) >= 0) {
        bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
        return EXIT_ERROR;
    }

    sr->file_info = bf_file_get_info(sr->real_path.data);

    if (!sr->file_info) {
        /* 如果被请求的资源不存在，则向插件请求看是否能处理 */
        BF_TRACE("No file, look for handler plugin");
        ret = bf_plugin_stage_run(BF_PLUGIN_STAGE_30, cs->socket, NULL, cs, sr);
        if (ret == BF_PLUGIN_RET_CLOSE_CONX) {
            bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
            return EXIT_ABORT;
        } 
        else if (ret == BF_PLUGIN_RET_CONTINUE) {
            return BF_PLUGIN_RET_CONTINUE;
        }
        else if (ret == BF_PLUGIN_RET_END) {
            return EXIT_NORMAL;
        }

        bf_request_error(BF_CLIENT_NOT_FOUND, cs, sr);
        return -1;
    }

    /* 目录是否有效 */
    if (sr->file_info->is_directory == BF_FILE_TRUE) {
        /* 如果最后的 / 没有找到的话说明路径有问题，重新请求路径 */
        if (bf_http_directory_redirect_check(cs, sr) == -1) {
            BF_TRACE("Directory Redirect");

            return -1;
        }

        /* 寻找 index 文件 */
        bf_pointer index_file;
        index_file = bf_request_index(sr->real_path.data);

        if (index_file.data) {
            bf_free(sr->file_info);
            bf_pointer_free(&sr->real_path);

            sr->real_path = index_file;
            sr->file_info = bf_file_get_info(sr->path.data);
        }
    }

    /* 寻找 符号连接 文件 */
    if (sr->file_info->is_link == BF_FILE_TRUE) {
        if (config->symlink == BF_FALSE) {
            bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
            return EXIT_ERROR;
        }
        else {
            int n;
            char linked_file[MAX_PATH];
            n = readlink(sr->real_path.data, linked_file, MAX_PATH);
        }
    }

    /* Plugin Stage 30: 为这些请求寻找 handlers */
    ret = bf_plugin_stage_run(BF_PLUGIN_STAGE_30, cs->socket, NULL, cs, sr);
    BF_TRACE("[FD %i] STAGE_30 returned %i", cs->socket, ret);

    if (ret == BF_PLUGIN_RET_CLOSE_CONX) {
        if (sr->headers && sr->headers->status > 0) {
            bf_request_error(sr->headers->status, cs, sr);
        }
        else {
            bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
        }
        return EXIT_ERROR;
    }
    else if (ret == BF_PLUGIN_RET_END) {
        return EXIT_NORMAL;
    }

    /* 读允许和检查文件 */
    if (sr->file_info->read_access == BF_FILE_FALSE) {
        bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
        return EXIT_ERROR;
    }

    /* 匹配 mimetype */
    mime = bf_mimetype_find(&sr->real_path);
    if (!mime) {
        mime = mimetype_default;
    }

    if (sr->file_info->is_directory == BF_FILE_TRUE) {
        bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
        return EXIT_ERROR;
    }

    /* 得到文件大小 */
    if (sr->file_info->size < 0) {
        bf_request_error(BF_CLIENT_NOT_FOUND, cs, sr);
        return EXIT_ERROR;
    }

    /* 计算连接数 */
    sr->headers->pconnection_left = (int) (config->max_keep_alive_request - cs->counter_connections);

    sr->headers->last_modified = sr->file_info->last_modification;

    if (sr->if_modified_since.data && sr->method == HTTP_METHOD_GET) {
        time_t date_client; /* Date sent by client */
        time_t date_file_server; /* Date server file */

        date_client = bf_utils_gmt2utime(sr->if_modified_since.data);
        date_file_server = sr->file_info->last_modification;

        if ((date_file_server <= date_client) && (date_client > 0)) {
            bf_header_set_http_status(sr, BF_NOT_MODIFIED);
            bf_header_send(cs->socket, cs, sr);
            return EXIT_NORMAL;
        }
    }
    bf_header_set_http_status(sr, BF_HTTP_OK);
    sr->headers->location = NULL;

    /* Object size for log and response headers */
    sr->headers->content_length = sr->file_info->size;
    sr->headers->real_length = sr->file_info->size;

    /* process method */
    if (sr->method == HTTP_METHOD_GET || sr->method == HTTP_METHOD_HEAD) {
        sr->headers->content_type = mime->type;
        /* range */
        if (sr->range.data != NULL && config->resume == BF_TRUE) {
            if (bf_http_range_parse(sr) < 0) {
                bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
                return EXIT_ERROR;
            }
            if (sr->headers->ranges[0] >= 0 || sr->headers->ranges[1] >= 0) {
                bf_header_set_http_status(sr, BF_HTTP_PARTIAL);
            }
        }
    }
    else {
        /* 不在 content-type 中 */
        bf_pointer_reset(&sr->headers->content_type);
    }

    /* 打开文件 */
    if (sr->file_info->size > 0) {
        sr->fd_file = open(sr->real_path.data, config->open_flags);
        if (sr->fd_file == -1) {
            BF_TRACE("open() failed");
            bf_request_error(BF_CLIENT_FORBIDDEN, cs, sr);
            return EXIT_ERROR;
        }
    }

    /* 发送 headers */
    bf_header_send(cs->socket, cs, sr);

    if (sr->headers->content_length == 0) {
        return 0;
    }

    /* 发送文件内容 */
    if (sr->method == HTTP_METHOD_GET || sr->method == HTTP_METHOD_POST) {
        if (bf_http_range_set(sr, sr->file_info->size) != 0) {
            bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
            return EXIT_ERROR;
        }

        bytes = bf_http_send_file(cs, sr);
    }

    return bytes;
}

int bf_http_send_file(struct client_session *cs, struct session_request *sr) {
    long int nbytes = 0;

    nbytes = bf_socket_send_file(cs->socket, sr->fd_file,
                                 &sr->bytes_offset, sr->bytes_to_send);

    if (nbytes > 0) {
        if (sr->loop == 0) {
            bf_socket_set_cork_flag(cs->socket, TCP_CORK_OFF);
        }
        sr->bytes_to_send -= nbytes;
    }

    sr->loop++;
    return sr->bytes_to_send;
}

int bf_http_directory_redirect_check(struct client_session *cs, session_request *sr) {
    char *host;
    char *location = 0;
    cahr *real_location = 0;
    unsigned long len;

    /* 如果最后的 '/' 没有找到的话说明路径有问题，重新请求路径 */
    if (sr->uri_process.data[sr->uri.len - 1] == '/') {
        return 0;
    }

    host = bf_pointer_to_buf(sr->host);

    /* 添加最后的 '/' */
    location = bf_alloc(sr->uri_process.len + 2);
    memcpy(location, sr->uri_process.data, sr->uri_process.len);
    location[sr->uri_process.len] = '/';
    location[sr->uri_process.len + 1] = '\0';

    if (config->serverport == config->standard_port) {
        bf_string_build(&read_location, &len, "%s://%s%s", config->transport, host, location);
    }
    else {
        bf_string_build(&read_location, &len, "%s://%s:%i%s", config->transport, host, config->serverport, location);
    }

#ifdef BF_TRACE
    BF_TRACE("Redirectiong to '%s'", read_location);
#endif

    bf_free(host);

    bf_header_set_http_status(sr, BF_REDIR_MOVED);
    sr->headers->content_length = 0;

    bf_pointer_reset(&sr->headers->content_type);
    sr->headers->location = real_location;
    sr->headers->cgi = SH_NOCGI;
    sr->headers->pconnection_left = (config->max_keep_alive_request - cs_counter_connections);
    bf_header_send(cs->socket, cs, sr);
    bf_socket_set_cork_flag(cs->socket, TCP_CORK_OFF);

    /* 
     *  我们不需要 free() real_location 
     *  因为它在 iov 中被free
     */
    bf_free(location);
    sr->headers->location = NULL;
    return -1;
}

int bf_keepalive_check(int socket, struct client_session *cs) {
    struct session_request *sr_node;
    struct bf_queue_s *sr_head;

    if (bf_queue_is_empty(&cs->request_list) == 0) {
        return -1;
    }

    sr_head = &cs->request_list;
    sr_node = bf_queue_entry_last(sr_head, struct session_request, _head);
    if (config->keep_alive == BF_FALSE || sr_node->keep_alive == BF_FALSE) {
        return -1;
    }

    /* Old client without Connection header */
    if (sr_node->protocol < HTTP_PROTOCOL_11 && sr_node->connection.len <= 0) {
        return -1;
    }

    /* Old client and content length to send is unknown */
    if (sr_node->protocol < HTTP_PROTOCOL_11 && sr_node->headers->content_length <= 0) {
        return -1;
    }

    /* Connection was forced to close */
    if (sr_node->close_now == BF_TRUE) {
        return -1;
    }

    /* Client has reached keep-alive connections limit */
    if (cs->counter_connections >= config->max_keep_alive_request) {
        return -1;
    }

    return 0;
}

int bf_http_range_set(struct session_request *sr, long file_size) {
    struct response_headers *sh = sr->headers;

    sr->bytes_to_send = file_size;
    sr->bytes_offset = 0;

    if (config->resume == BF_TRUE && sr->range.data) {
        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            sr->bytes_offset = sh->ranges[0];
            sr->bytes_to_send = file_size - sr->bytes_offset;
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            sr->bytes_offset = sh->ranges[0];
            sr->bytes_to_send = labs(sh->ranges[1] - sh->ranges[0]) + 1;
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            sr->bytes_to_send = sh->ranges[1];
            sr->bytes_offset = file_size - sh->ranges[1];
        }

        if (sr->bytes_offset > file_size || sr->bytes_to_send > file_size) {
            return -1;
        }

        lseek(sr->fd_file, sr->bytes_offset, SEEK_SET);
    }
    return 0;
}

int bf_http_range_parse(struct session_request *sr) {
    int eq_pos, sep_pos, len;
    char *buffer = 0;
    struct response_headers *sh;

    if (!sr->range.data) {
        return -1;
    }

    if ((eq_pos = bf_string_char_search(sr->range.data, '=', sr->range.len)) < 0) {
        return -1;
    }

    if (strncasecmp(sr->range.data, "Bytes", eq_pos) != 0) {
        return -1;
    }

    if ((sep_pos = bf_string_char_search(sr->range.data, '-', sr->range.len)) < 0) {
        return -1;
    }

    len = sr->range.len;
    sh = sr->headers;

    /* =-xxx */
    if (eq_pos + 1 == sep_pos) {
        sh->ranges[0] = -1;
        sh->ranges[1] = (unsigned long) atol(sr->range.data + sep_pos + 1);

        if (sh->ranges[1] <= 0) {
            return -1;
        }

        sh->content_length = sh->ranges[1];
        return 0;
    }

    /* =yyy-xxx */
    if ((eq_pos + 1 != sep_pos) && (len > sep_pos + 1)) {
        buffer = bf_string_copy_substr(sr->range.data, eq_pos + 1, sep_pos);
        sh->ranges[0] = (unsigned long) atol(buffer);
        bf_free(buffer);

        buffer = bf_string_copy_substr(sr->range.data, sep_pos + 1, len);
        sh->ranges[1] = (unsigned long) atol(buffer);
        bf_free(buffer);

        if (sh->ranges[1] <= 0 || (sh->ranges[0] > sh->ranges[1])) {
            return -1;
        }

        sh->content_length = abs(sh->ranges[1] - sh->ranges[0]) + 1;
        return 0;
    }
    /* =yyy- */
    if ((eq_pos + 1 != sep_pos) && (len == sep_pos + 1)) {
        buffer = bf_string_copy_substr(sr->range.data, eq_pos + 1, len);
        sr->headers->ranges[0] = (unsigned long) atol(buffer);
        bf_free(buffer);

        sh->content_length = (sh->content_length - sh->ranges[0]);
        return 0;
    }

    return -1;
}

/* 
 * 检查客户端请求是否还有未发送的数据
 * 
 * 0 所有数据都已经到达 
 * -1 因为HTTP的延迟，所有连接还有数据要发送 
 *
 * 函数从 request.c :: bf_handler_read(..) 调用
 */
int bf_http_pending_request(struct client_session *cs) {
    int n;
    char *end;

    if (cs->body_length >= bf_endblock.len) {
        end = (cs->body + cs->body_length) - bf_endblock.len;
    }
    else {
        return -1;
    }

    /* 匹配 最后的CRLF */
    if (cs->body_pos_end < 0) {
        if (strncmp(end, bf_endblock.data, bf_endblock.len) == 0) {
            cs->body_pos_end = cs->body_length - bf_endblock.len;
        }
        else if ((n = bf_string_search(cs->body, bf_endblock.data, BF_STR_SENSITIVE)) >= 0) {
            cs->body_pos_end = n;
        }
        else {
            return -1;
        }
    }

    if (cs->first_method == HTTP_METHOD_UNKNOWN) {
        cs->first_method = bf_http_method_get(cs->body);
    }

    if (cs->first_method == HTTP_METHOD_POST) {
        if (cs->body_pos_end > 0) {
            int content_length;
            int current;

            content_length = bf_method_post_content_length(cs->body);
            current = cs->body_length - cs->body_pos_end - bf_endblock.len;

            BF_TRACE("HTTP POST DATA %i/%i", current, content_length);
            if (content_length >= config->max_request_size) {
                return 0;
            }

            /* 如果第一个block结束了，我们需要验证在此之前是否有上一个block的结束
             * 这也意味着 POST 方法发送了全部信息
             * pipelining 不允许用 POST (仅供参考)
             */
            if (cs->body_pos_end == cs->body_length - bf_endblock.len) {
                /* 需要 content-length 
                 * 如果没有的话，先把状态设置为完成
                 * 最后再进行错误收集
                 */
                if (content_length <= 0) {
                    cs->status = BF_REQUEST_STATUS_COMPLETED;
                    return 0;
                }
                else {
                    return -1;
                }
            }
            else {
                if (current < content_length) {
                    return -1;
                }
                else {
                    cs->status = BF_REQUEST_STATUS_COMPLETED;
                    return 0;
                }
            }
        }
        else {
            return -1;
        }
    }

    cs->status = BF_REQUEST_STATUS_COMPLETED;
    return 0;
}

bf_pointer *bf_http_status_get(short int code) {
    bf_queue_sint_t *l;

    l = bf_http_status_list;
    while (l) {
        if (l->index == code) {
            return &l->value;
        }
        else {
            l = l->next;
        }
    }

    return NULL;
}

void bf_http_status_add(short ine val[2]) {
    short i, len = 6;
    char *str_val;
    bf_queue_sint_t *list, *_new;

    for (i = val[0]; i <= val[1]; i++) {
        _new = bf_alloc(sizeof(bf_queue_sint_t));
        _new->index = i;
        _new->next = NULL;

        str_val = bf_alloc(6);
        snprintf(str_val, len - 1, "%i", i);

        _new->value.data = str_val;
        _new-value.len = 3;

        if (!bf_http_stauts_list) {
            bf_http_status_list = _new;
        }
        else {
            list = bf_http_status_list;
            while (list->next) {
                list = list->next;
            }

            list->next = _new;
            list = _new;
        }
    }
}

void bf_http_status_list_init() {
    /* status type */
    short int success[2] = {200, 206};
    short int redirections[2] = {300, 305};
    short int client_errors[2] = {400, 415};
    short int server_errors[2] = {500, 505};

    bf_http_status_add(success);
    bf_http_status_add(redirections);
    bf_http_status_add(client_errors);
    bf_http_status_add(server_errors);
}

int bf_http_request_end(int socket) {
    int ka;
    struct client_session *cs;
    struct sched_list_node *sched;

    sched = bf_sched_get_thread_conf();
    cs = bf_session_get(socket);

    if (!cs) {
        BF_TRACE("[FD %i] Not found", socket);
        return -1;
    }

    if (!sched) {
        BF_TRACE("Could not find sched list node :/");
        return -1;
    }

    /* 检查是否为长连接 */
    ka = bf_http_keepalive_check(socket, cs);
    bf_request_free_list(cs);

    if (ka < 0) {
        BF_TRACE("[FD %i] No Keepalive mode, remove", cs->socket);
        bf_session_remove(socket);
    }
    else {
        bf_request_ka_next(cs);
        bf_epoll_change_mode(sched->epoll_fd, socket, BF_EPOLL_READ);
        return 0;
    }

    return -1;
}