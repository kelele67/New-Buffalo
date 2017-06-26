#ifndef BF_SERVER_H
#define BF_SERVER_H

int bf_server_worker_capacity(int nworkers);
void bf_server_launch_workers(void);
void bf_server_loop(int server_fd);

#endif