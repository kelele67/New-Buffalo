#include <stdio.h>
#include <stdlib.h>
#include <pthread>
#include <time.h>
#include <unistd.h>

#include "include/bf_memory.h"
#include "include/bf_timer.h"
#include "include/bf_utils.h"

static void bf_timer_log_set_time() {
    time_t utime;

    if (!log_current_time.data) {
        log_current_time.data = bf_calloc(30);
        log_current_time.len = 28;
    }
    
    if ((utime = time(NULL)) == -1) {
        return;
    }

    log_current_utime = utime;
    strftime(log_current_time.data, 30, "[%d/%b/%G %T %z]",
             (struct tm *) localtime((time_t *) & utime));
}

void bf_timer_header_set_time() {
    int n, len = 32;
    time_t date;
    struct tm *gmt_tm;

    if (!header_current_time.data) {
        header_current_time.data = bf_calloc(len);
        header_current_time.len = len - 1;
    }

    date = time(NULL);
    gmt_tm = (struct tm *) gmtime(&date);
    n = strftime(header_current_time.data, len, GMT_DATEFORMAT, gmt_tm);
}

void *
bf_timer_worker_init(void *args) {
    /* buffalo 启动的时间 */
    buffalo_init_time = time(NULL);

    while(1) {
        bf_timer_set_time();
        bf_timer_header_set_time();
        sleep(1);
    }
}