#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "include/buffalo.h"
#include "include/bf_config.h"
#include "include/bf_memory.h"
#include "include/bf_request.h"
#include "include/bf_header.h"
#include "include/bf_http.h"
#include "include/bf_iov.h"
#include "include/bf_user.h"

//#define bf_memzero(buf, n)  (void) memset(buf, 0, n)
//#define bf_memset(buf, c, n) (void) memset(buf, c, n)

/** 
 *封装了malloc函数 
 */
inline ALLOCSZ_ATTR(1)
void *
bf_alloc(const size_t size) {
    void *p;
    //分配一块内存
    p = malloc(size);
    if (p == NULL) {
        perror("malloc");
        return NULL;
    }
    return p;
}

/**
 * 调用bf_alloc方法，如果分配成功，则调用bf_memzero将内存块设置为0
 */
inline ALLOCSZ_ATTR(1)
void *
bf_calloc(const size_t size) {
    void *p;
    p = bf_alloc(size);
    if (p) {
        memset(p, '\0', size);
    }
    return p;
}

inline ALLOCSZ_ATTR(1, 2)
void *
bf_realloc(void *ptr, const size_t size) {
    void *p;
    p = realloc(ptr, size);

    if (p == NULL) {
        perror("realloc");
        return NULL;
    }
    return p;
}

void bf_free(void *ptr) {
    free(ptr);
}

bf_pointer bf_pointer_create(char *buf, long init, long end) {
    bf_pointer p;
    bf_pointer_reset(&p);
    p.data = buf + init;

    if (init != end) {
        p.len = (end - init);
    } else {
        p.len = 1;
    }
    return p;
}

void bf_pointer_reset(bf_pointer * p) {
    p->data = NULL;
    p->len = 0;
}

void bf_pointer_free(bf_pointer * p) {
    bf_free(p->data);
    p->len = 0;
}

char *bf_pointer_to_buf(bf_pointer p) {
    char *buf;

    buf = bf_alloc(p.len + 1);
    memcpy(buf, p.data, p.len);
    buf[p.len] = '\0';

    return (char *) buf;
}

void bf_pointer_print(bf_pointer p) {
    int i;

    printf("\nDEBUG BF_POINTER: '");
    for (i = 0; i < p.len && p.data != NULL; i++) {
        printf("%c", p.data[i]);
    } 
    printf("'");
    /* fflush()用于清空文件缓冲区，如果文件是以写的方式打开的，则把缓冲区内容写入文件 */
    fflush(stdout);
}

void bf_pointer_set(bf_pointer * p, char *data) {
    p->data = data;
    p->len = strlen(data);
}

void bf_pointers_init() {
    /* short 服务器响应 headers */
    bf_pointer_set(&bf_header_short_date, BF_HEADER_SHORT_DATE);
    bf_pointer_set(&bf_header_short_location, BF_HEADER_SHORT_LOCATION);
    bf_pointer_set(&bf_header_short_ct, BF_HEADER_SHORT_CT);

    /* 各种响应方式 */
    bf_pointer_set(&bf_crlf, BF_CRLF);
    bf_pointer_set(&bf_endblock, BF_ENDBLOCK);

    /* 客户端 headers */
    bf_pointer_set(&bf_rh_accept, RH_ACCEPT);
    bf_pointer_set(&bf_rh_accept_charset, RH_ACCEPT_CHARSET);
    bf_pointer_set(&bf_rh_accept_encoding, RH_ACCEPT_ENCODING);
    bf_pointer_set(&bf_rh_accept_language, RH_ACCEPT_LANGUAGE);
    bf_pointer_set(&bf_rh_connection, RH_CONNECTION);
    bf_pointer_set(&bf_rh_cookie, RH_COOKIE);
    bf_pointer_set(&bf_rh_content_length, RH_CONTENT_LENGTH);
    bf_pointer_set(&bf_rh_content_range, RH_CONTENT_RANGE);
    bf_pointer_set(&bf_rh_content_type, RH_CONTENT_TYPE);
    bf_pointer_set(&bf_rh_if_modified_since, RH_IF_MODIFIED_SINCE);
    bf_pointer_set(&bf_rh_host, RH_HOST);
    bf_pointer_set(&bf_rh_last_modified, RH_LAST_MODIFIED);
    bf_pointer_set(&bf_rh_last_modified_since, RH_LAST_MODIFIED_SINCE);
    bf_pointer_set(&bf_rh_referer, RH_REFERER);
    bf_pointer_set(&bf_rh_range, RH_RANGE);
    bf_pointer_set(&bf_rh_user_agent, RH_USER_AGENT);

    /* 服务器响应 normal headers */
    bf_pointer_set(&bf_header_conn_ka, BF_HEADER_CONN_KA);
    bf_pointer_set(&bf_header_conn_close, BF_HEADER_CONN_CLOSE);
    bf_pointer_set(&bf_header_content_length, BF_HEADER_CONTENT_LENGTH);
    bf_pointer_set(&bf_header_content_encoding, BF_HEADER_CONTENT_ENCODING);
    bf_pointer_set(&bf_header_accept_ranges, BF_HEADER_ACCEPT_RANGES);
    bf_pointer_set(&bf_header_te_chunked, BF_HEADER_TE_CHUNKED);
    bf_pointer_set(&bf_header_last_modified, BF_HEADER_LAST_MODIFIED);

    bf_http_status_list_init();
    bf_iov_separators_init();

    /* Server */
    bf_pointer_set(&bf_monkey_protocol, HTTP_PROTOCOL_11_STR);

    /* HTTP */
    bf_pointer_set(&bf_http_method_get_p, HTTP_METHOD_GET_STR);
    bf_pointer_set(&bf_http_method_post_p, HTTP_METHOD_POST_STR);
    bf_pointer_set(&bf_http_method_head_p, HTTP_METHOD_HEAD_STR);
    bf_pointer_reset(&bf_http_method_null_p);

    bf_pointer_set(&bf_http_protocol_09_p, HTTP_PROTOCOL_09_STR);
    bf_pointer_set(&bf_http_protocol_10_p, HTTP_PROTOCOL_10_STR);
    bf_pointer_set(&bf_http_protocol_11_p, HTTP_PROTOCOL_11_STR);
    bf_pointer_reset(&bf_http_protocol_null_p);
}