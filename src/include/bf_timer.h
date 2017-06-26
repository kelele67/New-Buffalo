#ifndef BF_TIMER_H
#define BF_TIMER_H

#include <time.h>
#include "bf_memory.h"

time_t log_current_utime;
time_t buffalo_init_time;

bf_pointer log_current_time;
bf_pointer header_current_time;

#define GMT_DATEFORMAT "%a, %d %b %Y %H:%M:%S GMT\r\n"

void *bf_timer_worker_init(void *args);
void bf_timer_set_time(void);

#endif