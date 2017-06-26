#ifndef BF_METHOD_H
#define BF_METHOD_H

int bf_method_post(struct client_session *cd, struct session_request *sr);
bf_pointer bf_method_post_get_vars(void *data, int size);
long int bf_method_post_content_length(char *body);

#endif