#include "bf_memory.h"
#include "bf_scheduler.h"

#ifndef BF_REQUEST_H
#define BF_REQUEST_H

/* request buffer chunks = 4KB */
#define BF_REQUEST_CHUNK (int) 4096
#define BF_REQUEST_DEFAULT_PAGE "<HTML><HEAD><STYLE type=\"text/css\"> body {font-size: 12px;} </STYLE></HEAD><BODY><H1>%s</H1>%s<BR><HR><ADDRESS>Powered by %s</ADDRESS></BODY></HTML>"

#define BF_CRLF "\r\n"
#define BF_ENDBLOCK "\r\n\r\n"

bf_pointer bf_crlf;
bf_pointer bf_endblock;

/* Headers 16 */
#define RH_ACCEPT "Accept:"
#define RH_ACCEPT_CHARSET "Accept-Charset:"
#define RH_ACCEPT_ENCODING "Accept-Encoding:"
#define RH_ACCEPT_LANGUAGE "Accept-Language:"
#define RH_CONNECTION "Connection:"
#define RH_COOKIE "Cookie:"
#define RH_CONTENT_LENGTH "Content-Length:"
#define RH_CONTENT_RANGE "Content-Range:"
#define RH_CONTENT_TYPE "Content-Type:"
#define RH_IF_NODIFIED_SINCE "If-Modified-Since:"
#define RH_HOST "Host:"
#define RH_LAST_MODIFIED "Last-Modified"
#define RH_LAST_MODIFIED_SINCE "Last-Modified-Since"
#define RH_REFERER "Referer:"
#define RH_RANGE "Range:"
#define RH_USER_AGENT "User-Agent:"

bf_pointer bf_rh_accept;
bf_pointer bf_rh_accept_charset;
bf_pointer bf_rh_accept_encoding;
bf_pointer bf_rh_accept_language;
bf_pointer bf_rh_connection;
bf_pointer bf_rh_cookie;
bf_pointer bf_rh_content_length;
bf_pointer bf_rh_content_range;
bf_pointer bf_rh_content_type;
bf_pointer bf_rh_if_modified_since;
bf_pointer bf_rh_host;
bf_pointer bf_rh_last_modified;
bf_pointer bf_rh_last_modified_since;
bf_pointer bf_rh_referer;
bf_pointer bf_rh_range;
bf_pointer bf_rh_user_agent;

/* 这里记录了暂时的请求参数 */
#define MAX_REQUEST_METHED 10
#define MAX_REQUEST_URI 1025
#define MAX_REQUEST_PROTOCOL 10
#define MAX_SCRIPTALIAS 3

#define BF_REQUEST_STATUS_INCOMPLETE -1
#define BF_REQUEST_STATUS_COMPLETED 0

#define EXIT_NORMAL 0
#define EXIT_ERROR -1
#define EXIT_ABORT -2 
#define EXIT_PCONNECTION 24

#define BF_HEADERS_TOC_LEN 32

struct client_session {
    int pipelined; /* 管道请求 */
    int socket;
    int counter_connections; /* 统计现有的连接 */
    int status; /* 请求状态 */
    char *body; /* 原始的发送请求 */

    bf_pointer *ipv4;

    int body_size;
    int body_length;

    int body_pos_end;
    int first_method;

    time_t init_time;

    struct bf_queue_s request_list;
    struct bf_queue_s _head;
};

pthread_key_t request_list;

struct header_toc {
    char *init;
    char *end;
    int status;   /* 0: not found, 1: found = skip! */
    struct header_toc *next;
};

/* 请求插件 handler 每个request 可以被多个插件 handle 并且在简单的
 *list 里面 hanle list
 */
struct handler {
     struct plugin *p;
     struct handler *next;
 };

struct session_request {
     int status;

     int pipelined;
     bf_pointer body;

     /* HTTP Headers Table of Content */
     struct header_toc headers_toc[BF_HEADERS_TOC_LEN];
     int headers_len;

    /*----First header of client request--*/
    int method;
    bf_pointer method_p;
    bf_pointer uri; /* original request */
    bf_pointer uri_processed; /* processed request (decoded) */

    int protocol;
    bf_pointer protocol_p;

    /* If request specify Connection: close, Buffalo will
     * close the connection after send the response, by
     * default this var is set to VAR_OFF;
     */
    int close_now;

    /* request headers */
    int content_length;

    bf_pointer accept;
    bf_pointer accept_charset;
    bf_pointer accept_encoding;
    bf_pointer accept_language;

    bf_pointer connection;
    bf_pointer cookies;
    bf_pointer content_type;

    bf_pointer host;
    bf_pointer host_port;
    bf_pointer if_modified_since;
    bf_pointer last_modified_since;
    bf_pointer referer;
    bf_pointer range;
    bf_pointer resume;
    bf_pointer user_agent;

    /*---------------------*/

    /* POST */
    bf_pointer post_variables;

    /*---------------------*/

    /* Internal */
    bf_pointer real_path;
    bf_pointer query_string;

    char *virtual_user; /* Virtualhost user */

    int keep_alive;
    int user_home; /* user_home request(VAR_ON/VAR_OFF) */

    /* Connection */
    long port;

    /*-----------*/

    /* fd */
    int fd_file;

    struct file_info *file_info;
    struct host *host_conf;
    struct response_headers *headers; /* headers response */

    long loop;
    long bytes_to_send;
    off_t bytes_offset;

    /* plugin handlers */
    struct plugin *handle_by;

    struct bf_queue_s _head;
};

struct response_headers {
    int status;

    /* Length of the content to send */
    long content_length;

    /* private value, real length of the file request */
    long ral_legnth;

    int cgi;
    int pconnecions_left;
    int ranges[2];
    int transfer_enconding;
    int breakline;

    time_t last_modified;
    bf_pointer content_type;
    bf_pointer content_encoding;
    char *location;

    /* 
     * This field allow plugins to add their own response
     * headers 消息回复结构体
     */
    struct bf_iov *_extra_rows;
};

bf_pointer bf_request_index(char *pathfile);
bf_pointer bf_request_header_get(struct header_toc *toc, bf_pointer header);

void bf_request_error(int http_status, struct client_session *cs, struct session_request *sr);

void bf_request_free_list(struct client_session *cs);

struct client_session *bf_session_create(int socket);
struct client_session *bf_session_get(int socket);
void bf_session_remove(int socket);

void bf_request_init_error_msgs(void);

int bf_handler_read(int socket, struct client_session *cs);
int bf_handler_write(int socket, struct client_session *cs);

void bf_request_header_toc_init(struct header_toc *toc);

void bf_request_ka_next(struct client_session *cs);

#endif