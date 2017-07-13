#ifndef BF_HTTP_H
#define BF_HTTP_H

#define HTTP_DIRECTORY_BACKWARD ".."

/* Methods */
#define HTTP_METHOD_UNKNOWN (-1)
#define HTTP_METHOD_GET (0)
#define HTTP_METHOD_POST (1)
#define HTTP_METHOD_HEAD (2)

#define HTTP_METHOD_GET_STR "GET"
#define HTTP_METHOD_POST_STR "POST"
#define HTTP_METHOD_HEAD_STR "HEAD"

#include "bf_memory.h"

bf_pointer bf_http_method_get_p;
bf_pointer bf_http_method_post_p;
bf_pointer bf_http_method_head_p;
bf_pointer bf_http_method_null_p;

/* Method status */
#define METHOD_NOT_ALLOWED (-1)
#define METHOD_NOT_FOUND (-2)
#define METHOD_EMPTY (-3)

#define HTTP_PROTOCOL_UNKNOWN (-1)
#define HTTP_PROTOCOL_09 (9)
#define HTTP_PROTOCOL_10 (10)
#define HTTP_PROTOCOL_11 (11)

#define HTTP_PROTOCOL_09_STR "HTTP/0.9"
#define HTTP_PROTOCOL_10_STR "HTTP/1.0"
#define HTTP_PROTOCOL_11_STR "HTTP/1.1"

bf_pointer bf_http_protocol_09_p;
bf_pointer bf_http_protocol_10_p;
bf_pointer bf_http_protocol_11_p;
bf_pointer bf_http_protocol_null_p;

#include "bf_request.h"

int bf_http_method_check(bf_pointer method);
bf_pointer bf_http_method_check_str(int method);
int bf_http_method_get(char *body);

int bf_http_protocol_check(char *proctocol, int len);
bf_pointer bf_http_protocol_check_str(int protocol);

int bf_http_init(struct client_session *cs, struct session_request *sr);
int bf_http_keepalive_check(int socket, struct client_session *cs);
int bf_http_directory_redirect_check(struct client_session *cs, struct session_request *sr);
int bf_http_range_set(struct session_request *sr, long file_size);
int bf_http_range_parse(struct session_request *sr);

bf_pointer *bf_http_status_get(short int code);
void bf_http_status_list_init(void);
int bf_http_pending_request(struct client_session *cs);
int bf_http_send_file(struct client_session *cs, struct session_request *sr);
int bf_http_request_end(int socket);

#endif