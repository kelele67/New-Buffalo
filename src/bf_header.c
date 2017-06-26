#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffalo.h"
#include "include/bf_header.h"
#include "include/bf_memory.h"
#include "include/bf_request.h"
#include "include/bf_iov.h"
#include "include/bf_http_status.h"
#include "include/bf_config.h"
#include "include/bf_socket.h"
#include "include/bf_utils.h"
#include "include/bf_clock.h"
#include "include/bf_cache.h"
#include "include/bf_http.h"
#include "include/bf_string.h"
#include "include/bf_debug.h"

static strcut header_status_response status_response[] = {
    /* 
     * 使用次数最多的:
     *
     *  - HTTP/1.1 200 OK
     *  - HTTP/1.1 404 Not Found
     */
    {BF_HTTP_OK,
     BF_RH_HTTP_OK,
     sizeof(BF_RH_HTTP_OK) - 1},
    {BF_CLIENT_NOT_FOUND, 
     BF_RH_CLIENT_NOT_FOUND,
     sizeof(BF_RH_CLIENT_NOT_FOUND) -1
    },

    /* Informational */
    {BF_INFO_CONTINUE,
     BF_RH_INFO_CONTINUE,
     sizeof(BF_RH_INFO_CONTINUE) - 1
    },
    {BF_INFO_SWITCH_PROTOCOL,
     BF_RH_INFO_SWITCH_PROTOCOL,
     sizeof(BF_RH_INFO_SWITCH_PROTOCOL) - 1
    },

    /* Successful */
    {BF_HTTP_CREATED,
     BF_RH_HTTP_CREATED,
     sizeof(BF_RH_HTTP_CREATED) - 1},
    {BF_HTTP_ACCEPTED,
     BF_RH_HTTP_ACCEPTED,
     sizeof(BF_RH_HTTP_ACCEPTED) - 1},
    {BF_HTTP_NON_AUTH_INFO,
     BF_RH_HTTP_NON_AUTH_INFO,
     sizeof(BF_RH_HTTP_NON_AUTH_INFO) - 1},
    {BF_HTTP_NOCONTENT,
     BF_RH_HTTP_NOCONTENT,
     sizeof(BF_RH_HTTP_NOCONTENT) - 1},
    {BF_HTTP_RESET,
     BF_RH_HTTP_RESET,
     sizeof(BF_RH_HTTP_RESET) - 1},
    {BF_HTTP_PARTIAL,
     BF_RH_HTTP_PARTIAL,
     sizeof(BF_RH_HTTP_PARTIAL) - 1},

    /* Redirections */
    {BF_REDIR_MULTIPLE,
     BF_RH_REDIR_MULTIPLE,
     sizeof(BF_RH_REDIR_MULTIPLE) - 1
    },
    {BF_REDIR_MOVED,
     BF_RH_REDIR_MOVED,
     sizeof(BF_RH_REDIR_MOVED) - 1
    },
    {BF_REDIR_MOVED_T,
     BF_RH_REDIR_MOVED_T,
     sizeof(BF_RH_REDIR_MOVED_T) - 1
    },
    {BF_REDIR_SEE_OTHER,
     BF_RH_REDIR_SEE_OTHER,
     sizeof(BF_RH_REDIR_SEE_OTHER) - 1
    },
    {BF_NOT_MODIFIED,
     BF_RH_NOT_MODIFIED,
     sizeof(BF_RH_NOT_MODIFIED) - 1
    },
    {BF_REDIR_USE_PROXY,
     BF_RH_REDIR_USE_PROXY,
     sizeof(BF_RH_REDIR_USE_PROXY) - 1
    },

    /* Client side errors */
    {BF_CLIENT_BAD_REQUEST, 
     BF_RH_CLIENT_BAD_REQUEST, 
     sizeof(BF_RH_CLIENT_BAD_REQUEST) - 1
    },
    {BF_CLIENT_UNAUTH,
     BF_RH_CLIENT_UNAUTH,
     sizeof(BF_RH_CLIENT_UNAUTH) - 1
    },
    {BF_CLIENT_PAYMENT_REQ,
     BF_RH_CLIENT_PAYMENT_REQ,
     sizeof(BF_RH_CLIENT_PAYMENT_REQ) - 1
    },
    {BF_CLIENT_FORBIDDEN, 
     BF_RH_CLIENT_FORBIDDEN,
     sizeof(BF_RH_CLIENT_FORBIDDEN) -1
    },
    {BF_CLIENT_METHOD_NOT_ALLOWED,
     BF_RH_CLIENT_METHOD_NOT_ALLOWED,
     sizeof(BF_RH_CLIENT_METHOD_NOT_ALLOWED) - 1
    },
    {BF_CLIENT_NOT_ACCEPTABLE,
     BF_RH_CLIENT_NOT_ACCEPTABLE,
     sizeof(BF_RH_CLIENT_NOT_ACCEPTABLE) - 1
    },
    {BF_CLIENT_PROXY_AUTH,
     BF_RH_CLIENT_PROXY_AUTH,
     sizeof(BF_RH_CLIENT_PROXY_AUTH) - 1
    },
    {BF_CLIENT_REQUEST_TIMEOUT,
     BF_RH_CLIENT_REQUEST_TIMEOUT,
     sizeof(BF_RH_CLIENT_REQUEST_TIMEOUT) - 1
    },
    {BF_CLIENT_CONFLICT,
     BF_RH_CLIENT_CONFLICT,
     sizeof(BF_RH_CLIENT_CONFLICT) - 1
    },
    {BF_CLIENT_GONE,
     BF_RH_CLIENT_GONE,
     sizeof(BF_RH_CLIENT_GONE) - 1
    },
    {BF_CLIENT_LENGTH_REQUIRED, 
     BF_RH_CLIENT_LENGTH_REQUIRED,
     sizeof(BF_RH_CLIENT_LENGTH_REQUIRED) - 1
    },
    {BF_CLIENT_PRECOND_FAILED,
     BF_RH_CLIENT_PRECOND_FAILED,
     sizeof(BF_RH_CLIENT_PRECOND_FAILED) - 1
    },
    {BF_CLIENT_REQUEST_ENTITY_TOO_LARGE,
     BF_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE,
     sizeof(BF_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE) - 1
    },
    {BF_CLIENT_REQUEST_URI_TOO_LONG,
     BF_RH_CLIENT_REQUEST_URI_TOO_LONG,
     sizeof(BF_RH_CLIENT_REQUEST_URI_TOO_LONG) - 1
    },
    {BF_CLIENT_UNSUPPORTED_MEDIA,
     BF_RH_CLIENT_UNSUPPORTED_MEDIA,
     sizeof(BF_RH_CLIENT_UNSUPPORTED_MEDIA) - 1
    },

    /* Server side errors */
    {BF_SERVER_INTERNAL_ERROR, 
     BF_RH_SERVER_INTERNAL_ERROR,
     sizeof(BF_RH_SERVER_INTERNAL_ERROR) - 1
    },
    {BF_SERVER_NOT_IMPLEMENTED,
     BF_RH_SERVER_NOT_IMPLEMENTED,
     sizeof(BF_RH_SERVER_NOT_IMPLEMENTED) - 1
    },
    {BF_SERVER_BAD_GATEWAY,
     BF_RH_SERVER_BAD_GATEWAY,
     sizeof(BF_RH_SERVER_BAD_GATEWAY) - 1
    },
    {BF_SERVER_SERVICE_UNAV,
     BF_RH_SERVER_SERVICE_UNAV,
     sizeof(BF_RH_SERVER_SERVICE_UNAV) - 1
    },
    {BF_SERVER_GATEWAY_TIMEOUT,
     BF_RH_SERVER_GATEWAY_TIMEOUT,
     sizeof(BF_RH_SERVER_GATEWAY_TIMEOUT) - 1
    },
    {BF_SERVER_HTTP_VERSION_UNSUP,
     BF_RH_SERVER_HTTP_VERSION_UNSUP,
     sizeof(BF_RH_SERVER_HTTP_VERSION_UNSUP)
    }
};

static int status_response_len = (sizeof(status_response) / (sizeof(status_response[0])));

int bf_header_iov_add_entry(struct bf_iov *bf_io, bf_pointer data, bf_pointer sep, int free) {
    return bf_iov_add_entry(bf_io, data.data, data.len, sep, free);
}

struct bf_iov *bf_header_iov_get() {
    return bf_cache_get(bf_cache_iov_header);
}

void bf_header_iov_free(struct bf_iov *iov) {
    bf_iov_free_marked(iov);
}

/* send header */
int bf_header_send(int fd, struct client_session *cs, struct session_request *sr) {
    int i, fd_status = 0;
    unsigned long len = 0;
    char *buffer = 0;
    bf_pointer response;
    struct response_headers *sh;
    struct bf_iov *iov;

    sh = sr->headers;

    iov = bf_header_iov_get();

    /* status code */
    for (i = 0; i < status_response_len; i++) {
        if (status_response[i].status == sh->status) {
            response.data = status_response[i].response;
            response.len = status_response[i].length;
            bf_header_iov_add_entry(iov, response, bf_iov_none, BF_IOV_NOT_FREE_BUF);
            break;
        }
    }

    /* invalid status */
    bf_bug(i == status_response_len);

    if (fd_status < 0) {
        bf_header_iov_free(iov);
        return -1;
    }

    /* server details */
    bf_iov_add_entry(iov, 
                     sr->host_conf->header_host_signature.data,
                     sr->host_conf->header_host_signature.len,
                     bf_iov_crlf, BF_IOV_NOT_FREE_BUF);
    
    /* date */
    bf_iov_add_entry(iov,
                     bf_header_short_date.data,
                     bf_header_short_date.len,
                     bf_iov_none, BF_IOV_NOT_FREE_BUF);

    bf_iov_add_entry(iov,
                     header_current_time.data,
                     header_current_time.len,
                     bf_iov_none, BF_IOV_NOT_FREE_BUF);

    /* last modified */
    if (sh->last_modified > 0) {
        bf_pointer *lm;
        lm = bf_cache_get(bf_cache_header_lm);
        bf_utils_utime2gmt(&lm, sh->last_modified);

        bf_iov_add_entry(iov,
                         bf_header_last_modified.data,
                         bf_header_last_modified.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
        bf_iov_add_entry(iov,
                         lm->data,
                         lm->len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
    }

    /* connection */
    if (bf_http_keepalive_check(fd, cs) == 0) {
        if (sr->connection.len > 0) {
            bf_string_build(&buffer,
                            &len,
                            "Keep-Alive: timeout=%i, max=%i"
                            BF_CRLF,
                            config->max_keep_alive_request - cs->counter_connections);
            bf_iov_add_entry(iov, buffer, len, bf_iov_none, BF_IOV_NOT_FREE_BUF);
            bf_iov_add_entry(iov,
                             bf_header_conn_ka.data,
                             bf_header_conn_ka.len,
                             bf_iov_none, BF_IOV_NOT_FREE_BUF);
        }
    }
    else {
        bf_iov_add_entry(iov,
                         bf_header_conn_close.data,
                         bf_header_conn_close.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
        bf_iov_add_entry(iov,
                         sh->location,
                         strlen(sh->location), bf_iov_crlf, BF_IOV_NOT_FREE_BUF);
    }

    /* content type */
    if (sh->content_type.len > 0) {
        bf_iov_add_entry(iov,
                         bf_header_short_ct.data,
                         bf_header_short_ct.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
        bf_iov_add_entry(iov,
                         sh->content_type.data,
                         sh->content_type.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
    }

    /* transfer encoding：当response有些内容由HTTP status response 定义的时候发送 */
    if ((sh->status < BF_REDIR_MULTIPLE) || (sh->status->BF_REDIR_USE_PROXY)) {
        switch(sh->transfer_encoding) {
            case BF_HEADER_TE_TYPE_CHUNKED:
                bf_iov_add_entry(iov,
                                 bf_header_te_chunked.data,
                                 bf_header_te_chunked.len,
                                 bf_iov_none, BF_IOV_NOT_FREE_BUF);
                break;
        }
    }

    /* content encoding */
    if (sh->content_encoding.len > 0) {
        bf_iov_add_entry(iov,
                         bf_header_content_encoding.data,
                         bf_header_content_encoding.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
        bf_iov_add_entry(iov,
                         sh->content_encoding.data,
                         sh->content_encoding.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
    }

    /* content length */
    if (sh->content_length >= 0) {
        bf_pointer *cl;
        cl = bf_cache_get(bf_cahce_header_cl);
        bf_string_itop(sh->content_length, cl);

        /* set headers */
        bf_iov_add_entry(iov,
                         bf_header_content_length.data,
                         bf_header_content_length.len,
                         bf_iov_none, BF_IOV_NOT_FREE_BUF);
        bf_iov_add_entry(iov,
                         cl->data,
                         cl->len,
                         bf_iov_none,
                         BF_IOV_NOT_FREE_BUF);
    }

    if ((sh->content_length != 0 && (sh->ranges[0] >= 0 || sh->ranges[1] >= 0)) && config->resume == BF_TRUE) {
        buffer = 0;

        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            bf_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            sh->ranges[0],
                            (sh->real_length - 1), sh->real_length);
            bf_iov_add_entry(iov, buffer, len, bf_iov_crlf, BF_IOV_FREE_BUF);
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            bf_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            sh->ranges[0], sh->ranges[1], sh->real_length);

            bf_iov_add_entry(iov, buffer, len, bf_iov_crlf, BF_IOV_FREE_BUF);
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            bf_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%d",
                            RH_CONTENT_RANGE,
                            (sh->real_length - sh->ranges[1]),
                            (sh->real_length - 1), sh->real_length);
            bf_iov_add_entry(iov, buffer, len, bf_iov_crlf, BF_IOV_FREE_BUF);
        }
    }

    /* 打开 cork */
    bf_socket_set_cork_flag(fd, TCP_CORK_ON);

    if (sh->cgi == SH_NOCGI || sh->breakline == BF_HEADER_BREAKLINE) {
        if (!sr->headers->_extra_rows) {
            bf_iov_add_entry(iov,
                             bf_iov_crlf.data,
                             bf_iov_crlf.len,
                             bf_iov_none, BF_IOV_NOT_FREE_BUF);
        }
        else {
            bf_iov_add_entry(sr->headers->_extra_rows,
                             bf_iov_crlf.data,
                             bf_iov_crlf.len,
                             bf_iov_none, BF_IOV_NOT_FREE_BUF);
        }
    }

    bf_socket_sendv(fd, iov);
    if (sr->headers->_extra_rows) {
        bf_socket_sendv(fd, sr->headers->_extra_rows);
    }

    bf_header_iov_free(iov);
    return 0;
}

char *bf_header_chunked_line(int len) {
    char *buf;

    buf = bf_calloc(10);
    snprintf(buf, 9, "%x%s", len, BF_CRLF);

    return buf;
}

void bf_header_set_http_status(struct session_request *sr, int status) {
    bf_bug(!sr || !sr->headers);
    sr->headers->status = status;
}

struct response_headers *bf_header_create() {
    struct response_headers *header;

    headers = bf_alloc(sizeof(struct response_headers));
    headers->status = 0;
    headers->ranges[0] = -1;
    headers->ranges[1] = -1;
    headers->content_length = -1;
    headers->transfer_encoding = -1;
    headers->last_modified = -1;
    headers->cgi = SH_NOCGI;
    bf_pointer_reset(&headers->content_type);
    bf_pointer_reset(&headers->content_encoding);
    headers->location = NULL;

    headers->_extra_rows = NULL;

    return headers;
}