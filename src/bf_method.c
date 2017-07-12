#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "include/buffalo.h"
#include "include/bf_string.h"
#include "include/bf_memory.h"
#include "include/bf_http.h"
#include "include/bf_http_status.h"
#include "include/bf_socket.h"
#include "include/bf_config.h"
#include "include/bf_utils.h"
#include "include/bf_file.h"
#include "include/bf_cache.h"

long int bf_method_post_content_length(char *body) {
    struct header_toc *toc = NULL;
    long int len;
    bf_pointer tmp;

    /* obs: Table of Content (toc) 在所有的 request 都到达时建立
     * 这个函数不能在正在接收 request 的时候使用：
     * bf_http_pending_request().
     */
    toc = bf_cache_get(bf_cache_header_toc);
    tmp = bf_request_header_get(toc, bf_rh_content_length);

    if (!tmp.data) {
        int pos_header;
        int pos_crlf;
        char *str_cl;

    /* 预解析方法：检查是否获取到了 content-length */
    pos_header = bf_string_search(body, RH_CONTENT_LENGTH, BF_STRING_INSENSITIVE);
    if (pos_header <= 0) {
        return -1;
    }

    pos_crlf = bf_string_search(body + pos_header, BF_IOV_CRLF, BF_STRING_SENSITIVE);
    if (pos_crlf <= 0) {
        return -1;
    }

    str_cl = bf_string_copy_substr(body + pos_header + bf_rh_content_length.len + 1,
                                    0, pos_header + pos_crlf);
    len = strtol(str_cl, (char **) NULL, 10);
    bf_free(str_cl);

    return len;
    }

    len = strtol(tmp.data, (char **) NULL, 10);
    return len;
}

/* POST METHOD */
int bf_method_post(struct client_session *cs, struct session_request *sr) {
    bf_pointer tmp;
    long content_length_post = 0;

    content_length_post = bf_method_post_content_length(cs->body);

    /* 需要长度 */
    if (content_length_post == -1) {
        bf_request_error(BF_CLIENT_LENGTH_REQUIRED, cs, sr);
        return -1;
    }

    /* 错误的 request */
    if (content_length_post <= 0) {
        bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
        return -1;
    }

    /* 长度太大 */
    if (content_length_post >= cs->body_size) {
        bf_request_error(BF_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs, sr);
        return -1;
    }

    tmp = bf_request_header_get(sr->headers_toc, bf_rh_content_type);
    if (!tmp.data) {
        bf_request_error(BF_CLIENT_BAD_REQUEST, cs, sr);
        return -1;
    }
    sr->content_type = tmp;
    sr->content_length = content_length_post;

    return 0;
}

/* Return POST variables sent in request */
bf_pointer bf_method_post_get_vars(void *data, int size) {
    bf_pointer p;

    p.data = data;
    p.len = size;

    return p;
}


