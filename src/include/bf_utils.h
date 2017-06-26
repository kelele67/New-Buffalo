#ifndef BF_UTILS_H
#define BF_UTILS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BF_UTILS_INT2BFP_BUFFER_LEN 16  /* int to bf_pointer 的最大 buffer 长度*/

#define BF_UTILS_SOMAXCONN_DEFAULT 1024 /* socket 最大连接数的默认值 */

#include "bf_request.h"
#include "bf_memory.h"
#include "bf_queue.h"

/* Trace */
#ifdef TRACE

#define BF_TRACE_CORE 0
#define BF_TRACE_PLUGIN 1
#define BF_TRACE_COMP_CORE "core"

#define BF_TRACE(...) bf_utils_trace(BF_TRACE_COMP_CORE, BF_TRACE_CORE, \
                                        __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);

#include "bf_plugin.h"

char *envtrace;
pthread_mutex_t mutex_trace;

#else
#define BF_TRACE(...) do {} while (0)
#endif

/* utils.c */
int bf_utils_utime2gmt(bf_pointer **p, time_t date);
time_t bf_utils_gmt2utime(char *date);

int bf_buffer_cat(bf_pointer * p, char *buf1, int len1, char *buf2, int len2);

int bf_utils_set_daemon(void);
char *bf_utils_url_decode(bf_pointer req_uri);

#ifdef TRACE
void bf_utils_trace(const char *component, int color, const char *function,
                    char *file, int line, const char* format, ...);

int bf_utils_print_errno(int errno);
#endif

int bf_utils_get_somaxconn(void);
int bf_utils_register_pid(void);
int bf_utils_remove_pid(void);

void bf_print(int type, const char *format, ...);

pthread_t bf_utils_worker_spawn(void (*func) (void*));

#endif