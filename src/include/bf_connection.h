#ifndef BF_CONNECTION_H
#define BF_CONNECTION_H

#define BF_CONN_SWITCH_READ 0
#define BF_CONN_SWITCH_WRITE 1

int bf_conn_switch(int action, int socket);
int bf_conn_switch_error(int socket);

int bf_conn_read(int socket);
int bf_conn_write(int socket);
int bf_conn_error(int socket);
int bf_conn_close(int socket);
int bf_conn_timeout(int socket);

#endif