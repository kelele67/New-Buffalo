#include "bf_request.h"
#include "bf_http_status.h"

#ifndef BF_HEADER_H
#define BF_HEADER_H

#define BF_HEADER_BREAKLINE 1

/* request response
 * 保存一些response 的状态
 */

/* Informational */
#define BF_RH_INFO_CONTINUE "HTTP/1.1 100 Continue\r\n"
#define BF_RH_INFO_SWITCH_PROTOCOL "HTTP/1.1 101 Switching Protocols\r\n"

/* Successfull */
#define BF_RH_HTTP_OK "HTTP/1.1 200 OK\r\n"
#define BF_RH_HTTP_CREATED "HTTP/1.1 201 Created\r\n"
#define BF_RH_HTTP_ACCEPTED "HTTP/1.1 202 Accepted\r\n"
#define BF_RH_HTTP_NON_AUTH_INFO "HTTP/1.1 203 Non-Authoritative Information\r\n"
#define BF_RH_HTTP_NOCONTENT "HTTP/1.1 204 No Content\r\n"
#define BF_RH_HTTP_RESET "HTTP/1.1 205 Reset Content\r\n"
#define BF_RH_HTTP_PARTIAL "HTTP/1.1 206 Partial Content\r\n"

/* Redirections */
#define BF_RH_REDIR_MULTIPLE "HTTP/1.1 300 Multiple Choices\r\n"
#define BF_RH_REDIR_MOVED "HTTP/1.1 301 Moved Permanently\r\n"
#define BF_RH_REDIR_MOVED_T "HTTP/1.1 302 Found\r\n"
#define	BF_RH_REDIR_SEE_OTHER "HTTP/1.1 303 See Other\r\n"
#define BF_RH_NOT_MODIFIED "HTTP/1.1 304 Not Modified\r\n"
#define BF_RH_REDIR_USE_PROXY "HTTP/1.1 305 Use Proxy\r\n"

/* Client side errors */
#define BF_RH_CLIENT_BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n"
#define BF_RH_CLIENT_UNAUTH "HTTP/1.1 401 Unauthorized\r\n"
#define BF_RH_CLIENT_PAYMENT_REQ "HTTP/1.1 402 Payment Required\r\n"
#define BF_RH_CLIENT_FORBIDDEN "HTTP/1.1 403 Forbidden\r\n"
#define BF_RH_CLIENT_NOT_FOUND "HTTP/1.1 404 Not Found\r\n"
#define BF_RH_CLIENT_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n"
#define BF_RH_CLIENT_NOT_ACCEPTABLE "HTTP/1.1 406 Not Acceptable\r\n"
#define BF_RH_CLIENT_PROXY_AUTH "HTTP/1.1 407 Proxy Authentication Required\r\n"
#define BF_RH_CLIENT_REQUEST_TIMEOUT "HTTP/1.1 408 Request Timeout\r\n"
#define BF_RH_CLIENT_CONFLICT "HTTP/1.1 409 Conflict\r\n"
#define BF_RH_CLIENT_GONE "HTTP/1.1 410 Gone\r\n"
#define BF_RH_CLIENT_LENGTH_REQUIRED "HTTP/1.1 411 Length Required\r\n"
#define BF_RH_CLIENT_PRECOND_FAILED "HTTP/1.1 412 Precondition Failed\r\n"
#define BF_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE \
  "HTTP/1.1 413 Request Entity Too Large\r\n"
#define BF_RH_CLIENT_REQUEST_URI_TOO_LONG "HTTP/1.1 414 Request-URI Too Long\r\n"
#define BF_RH_CLIENT_UNSUPPORTED_MEDIA  "HTTP/1.1 415 Unsupported Media Type\r\n"

/* Server side errors */
#define BF_RH_SERVER_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error\r\n"
#define BF_RH_SERVER_NOT_IMPLEMENTED "HTTP/1.1 501 Not Implemented\r\n"
#define BF_RH_SERVER_BAD_GATEWAY "HTTP/1.1 502 Bad Gateway\r\n"
#define BF_RH_SERVER_SERVICE_UNAV "HTTP/1.1 503 Service Unavailable\r\n"
#define BF_RH_SERVER_GATEWAY_TIMEOUT "HTTP/1.1 504 Gateway Timeout\r\n"
#define BF_RH_SERVER_HTTP_VERSION_UNSUP "HTTP/1.1 505 HTTP Version Not Supported\r\n"

struct header_status_response {
    int status;
    char *response;
    int length;
};

/* short header values */
#define BF_HEADER_SHORT_DATE: "Date: "
#define BF_HEADER_SHORT_LOCATION "Location: "
#define BF_HEADER_SHORT_CT "Content-Type: "

bf_pointer bf_header_short_date;
bf_pointer bf_header_short_location;
bf_pointer bf_header_short_ct;

/* Accept ranges */
#define BF_HEADER_ACCEPT_RANGES "Accept-Ranges: bytes" BF_CRLF

#define BF_HEADER_CONN_KA "Connection: Keep-Alive" BF_CRLF
#define BF_HEADER_CONN_CLOSE "Connection: Close" BF_CRLF
#define BF_HEADER_CONTENT_LENGTH "Content-Length: "
#define BF_HEADER_CONTENT_ENCODING "Content-Encoding: "

/* Transfer Encoding */
#define BF_HEADER_TE_TYPE_CHUNKED 0
#define BF_HEADER_TE_CHUNKED "Transfer-Encoding: Chunked" BF_CRLF

#define BF_HEADER_LAST_MODIFIED "Last-Modified: "

/* bf pointers with response server headers */
bf_pointer bf_header_conn_ka;
bf_pointer bf_header_conn_close;
bf_pointer bf_header_content_length;
bf_pointer bf_header_content_encoding;
bf_pointer bf_header_accept_ranges;
bf_pointer bf_header_te_chunked;
bf_pointer bf_header_last_modified;

int bf_header_send(int fd, struct client_session *cs, struct session_request *sr);
struct response_headers *bf_header_create(void);
void bf_header_set_http_status(struct session_request *sr, int status);
void bf_header_set_content_length(struct session_request *sr, long len);

#endif