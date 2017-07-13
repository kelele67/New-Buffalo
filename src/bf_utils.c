#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>

#include "buffalo.h"
#include "bf_memory.h"
#include "bf_utils.h"
#include "bf_file.h"
#include "bf_string.h"
#include "bf_config.h"
#include "bf_socket.h"
#include "bf_timer.h"
#include "bf_user.h"
#include "bf_cache.h"
#include "bf_debug.h"

/* 日期函数 */
static const char *bf_date_wd[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char *bf_date_ym[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                              "Aug", "Sep", "Oct", "Nov", "Dec"};

/* 这个函数把 unix time转换成 GMT 格式
 * date 是 RFC1123 格式的 例如:
 *
 *    Sat, 20 May 2017 09:26:11 GMT
 *    
 * 并且在末尾加上了 'CRLF' 
 */
 int bf_utils_utime2gmt(bf_pointer **p, time_t date) {
     int size = 31;
     unsigned int year;
     char *buf = 0;
     struct tm *gtm;

     if (date == 0) {
         if ((date = time(NULL)) == -1) {
             return -1;
         }
     }

     /* 把unix time 放入 tm */
     gtm = bf_cache_get(bf_cache_utils_gmtime);
     gtm = gmtime_r(&date, gtm); /* 将日历时间 timep 转换为用 UTC 时间表示的时间，并储存到gtm结构体中 */
     if (!gtm) {
         return -1;
     }

     /* struct tm year -> gmt year */
     year = gtm->tm_year + 1900;

     /* Compose template */
     buf = (*p)->data;

     /* Week day */
     *buf++ = bf_date_wd[gtm->tm_wday][0];
     *buf++ = bf_date_wd[gtm->tm_wday][1];
     *buf++ = bf_date_wd[gtm->tm_wday][2];
     *buf++ = ',';
     *buf++ = ' ';

     /* Day of the month */
     *buf++ = ('0' + (gtm->tm_mday / 10));
     *buf++ = ('0' + (gtm->tm_mday % 10));
     *buf++ = ' ';

     /* Year month */
     *buf++ = bf_date_ym[gtm->tm_mon][0];
     *buf++ = bf_date_ym[gtm->tm_mon][1];
     *buf++ = bf_date_ym[gtm->tm_mon][2];
     *buf++ = ' ';

     /* Year */
     *buf++ = ('0' + (year / 1000) % 10);
     *buf++ = ('0' + (year / 100) % 10);
     *buf++ = ('0' + (year / 10) % 10);
     *buf++ = ('0' + (year % 10));
     *buf++ = ' ';

     /* Hour */
     *buf++ = ('0' + (gtm->tm_hour / 10));
     *buf++ = ('0' + (gtm->tm_hour % 10));
     *buf++ = ':';

     /* Minutes */
     *buf++ = ('0' + (gtm->tm_min / 10));
     *buf++ = ('0' + (gtm->tm_min % 10));
     *buf++ = ':';

     /* Seconds */
     *buf++ = ('0' + (gtm->tm_sec / 10));
     *buf++ = ('0' + (gtm->tm_sec % 10));
     *buf++ = ' ';

     /* add CRLF */
     *buf++ = 'G';
     *buf++ = 'M';
     *buf++ = 'T';
     *buf++ = '\r';
     *buf++ = '\n';
     *buf++ = '\0';

     /* set bf_pointer data len */
     (*p)->len = size;

     return 0;
 }

 time_t bf_utils_gmt2utime(char *date) {
     time_t new_unix_time;
     struct tm t_data;

     /* strptime将一个字符串格式化为一个struct tm结构 */
     if (!strptime(date, GMT_DATEFORMAT, (struct tm *) &t_data)) {
         return -1;
     }
     new_unix_time = bftime((struct tm *) &t_data);

     return (new_unix_time);
 }

int bf_buffer_cat(bf_pointer *p, char *buf1, int len1, char *buf2, int len2) {
    /* 长度是否有效 */
    if (len1 < 0 || len2 < 0) {
        return -1;
    }

    /* 分配空间 */
    p->data = (char *) bf_alloc(len1 + len2 + 1);

    /* 拷贝data */
    memcpy(p->data, buf1, len1);
    memcpy(p->data + len1, buf2, len2);
    p->data[len1 + len2] = '\0';

    /* 分配长度 */
    p->len = len1 + len2;

    return 0;
}

/* 建立守护进程 */
int bf_utils_set_daemon() {
    pid_t pid;

    umask(0); /* 为了在daemon 创建自己的文件时，文件权限位不受原有文件创建掩码的权限位的影响 */

    if ((pid = fork()) < 0) {
        err(EXIT_FAILURE, "pid");
    }

    /* parent */
    if (pid != 0) {
        exit(EXIT_FAILURE);
    }

    /* 确保我们更改了 daemon 的工作目录，用于满足 server 本身的处理需求 */
    if (chdir("/") < 0) {
        err(EXIT_FAILURE, "chdir");
    }

    /* 建立新的会话 session */
    setsid();

    /* 最后的 STDOUT 信息 */
    bf_info("Background mode ON");

    fclose(stderr);
    fclose(stdout);

    return 0;
}

/* 十六进制 hex 转换为 int */
int bf_utils_hex2int(char *hex, int len) {
    int i = 0;
    int value = 0;
    char c;

    while ((c = *hex++) && i < len) {
        value *= 0x10; /* 0x10 16*/

        if (c >= 'a' && c <= 'f') {
            value += (c - 0x57); /* c - 'a' + 10 (0x57->87 a->97) */
        }
        else if ( c>= 'A' && c <= 'F') {
            value += (c - 0x37); /* c - 'A' + 10 (0x37->55 A->65) */ 
        }
        else if (c >= '0' && c <= '9') {
            value += (c - 0x30); /* c - '0' (0x30->48 0->48) */
        }
        else {
            return -1;
        }
        i++;
    }

    if (value < 0) {
        return -1;
    }

    return value;
}

/* 如果url 有 hexa 字符 则 转为 ASCII */
char *bf_utils_url_decode(bf_pointer uri) {
    int i, hex_result;
    int buf_index = 0;
    char *buf;
    char hex[3];

    if ((i = bf_string_char_search(uri.data, '%', uri.len)) < 0) {
        return NULL;
    }

    buf = bf_calloc(uri.len);

    if (i > 0) {
        strncpy(buf, uri.data, i);
        buf_index = i;
    }

    while (i < uri.len) {
        if (uri.data[i] == '%' && i + 2 < uri.len) {
            memset(hex, '\0', sizeof(hex));
            strncpy(hex, uri.data + i + 1, 2);
            hex[2] = '\0';

            hex_result = bf_utils_hex2int(hex, 2);

            if (hex_result != -1) {
                buf[buf_index] = hex_result;
            } else {
                bf_free(buf);
                return NULL;
            }
            i += 2;
        } else {
            buf[buf_index] = uri.data[i];
        }
        i++;
        buf_index++;
    }
    buf[buf_index] = '\0';

    return buf;
}

#ifdef TRACE
#include <sys/time.h>
void bf_utils_trace(const char *component, int color, const char *function, char *file, int line, const char* format, ...) {
    va_list args;
    char *color_function = NULL;
    char *color_fileline = NULL;

    struct timeval tv;
    struct timezone tz;

    if (envtrace) {
        if (!strstr(envtrace, file)) {
            return;
        }
    }

    /* mutex lock */
    pthread_mutex_lock(&mutex_trace);

    gettimeofday(&tv, &tz);

    /* 消息 颜色 */
    switch(color) {
        case BF_TRACE_CORE:
            color_function = ANSI_YELLOW;
            color_fileline = ANSI_WHITE;
            break;
        case BF_TRACE_PLUGIN:
            color_function = ANSI_BLUE;
            color_fileline = ANSI_WHITE;
            break;
    }

    va_start( args, format );

    printf("~ %s%2i.%i%s %s%s[%s%s%s%s%s|%s:%i%s] %s%s():%s ",
            ANSI_CYAN, (int) (tv.tv_sec - buffalo_init_time), (int) tv.tv_usec, ANSI_RESET,
            ANSI_MAGENTA, ANSI_BOLD,
            ANSI_RESET, ANSI_BOLD, ANSI_GREEN, component, color_fileline, file,
            line, ANSI_MAGENTA,
            color_function, function, ANSI_RED);
    vprintf(format, args );
    va_end(args);
    printf("%s\n", ANSI_RESET);
    fflush(stdout);

    /* mutex unlock */
    pthread_mutex_unlock(&mutex_trace);
}

int bf_utils_print_errno(int errno) {
    switch(errno) {
        case EAGAIN: /* Try again */
            BF_TRACE("EAGAIN");
            return -1;
        case EBADF: /* Bad file number */
            BF_TRACE("EBADF");
            return -1;
        case EFAULT: /* Bad address */
            BF_TRACE("EFAULT");
            return -1;
        case EFBIG: /* File too large */
            BF_TRACE("EFBIG");
            return -1;
        case EINTR: /* Interrupted system call */
            BF_TRACE("EINTR");
            return -1;
        case EINVAL: /* Invalid argument */
            BF_TRACE("EINVAL");
            return -1;
        case EPIPE: /* Broken pipe */
            BF_TRACE("EPIPE");
            return -1;
        default:
            BF_TRACE("DONT KNOW");
            return 0;
    }

    return 0;
}

#endif

/* 得到 SOMAXCONN 的值， 基于 sysctl 的 manpage */
int bf_utils_get_somaxconn() {
    /* 由于 sysctl()在某些系统里面不支持，所以可能有会警告：
     * '(warning: process `buffalo' used the deprecated sysctl system call...'
     *
     * 为了避免这个警告，我们先检查系统的 proc文件系统，如果失败我们将用默认值作为somaxconn
     */
    long somaxconn = 128;
    char buf[16];
    FILE *f;

    f = open("/proc/sys/net/core/somaxconn", "r");
    if (f && fgets(buf, 16, f) {
        somaxconn = (buf, (char **) NULL, 10);
        fclose(f);
    }

    return (int) somaxconn;
}

/* 注册 Buffalo 的 PID */
int bf_utils_register_pid() {
    FILE *pid_file;
    unsigned long len = 0;
    char *filepath = NULL;

    bf_string_build(&filepath, &len, "%s.%d", config->pid_file_path, config->serverport);

    if ((pid_file = fopen(filepath, "w")) == NULL) {
        bf_err("Error: I can't log pid of buffalo");
        exit(EXIT_FAILURE);
    }

    fprint(pid_file, "%i", getpid());
    fclose(pid_file);
    bf_free(filepath);
    config->pid_status = BF_TRACE;

    return 0;
}

/* 移除 PID 文件 */
int bf_utils_remove_pid() {
    unsigned long len = 0;
    char *filepath = NULL;
    int ret;

    bf_string_build(&filepath, &len, "%s.%d", config->pid_file_path, config->serverport);

    bf_user_undo_uidgid();
    ret = unlink(filepath);
    bf_free(filepath);
    config->pid_status = BF_FALSE;
    return ret;
}

void bf_print(int type, const char *format, ...) {
    time_t now;
    struct tm *current;

    char *header_color = NULL;
    char *header_title = NULL;
    va_list args;

    va_start(args, format);

    switch(type) {
        case BF_INFO:
            header_title = "Info";
            header_color = ANSI_GREEN;
            break;
        case BF_ERR:
            header_title = "Error";
            header_color = ANSI_RED;
            break;
        case BF_WARN:
            header_title = "Warning";
            header_color = ANSI_YELLOW;
            break;
        case BF_BUG:
            header_title = "BUG!";
            header_color = ANSI_BOLD ANSI_RED;
    }

    now = time(NULL);
    current = localtime(&now);
    printf("%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
            ANSI_BOLD, ANSI_RESET,
            current->tm_year + 1900,
            current->tm_mon,
            current->tm_mday,
            current->tm_hour,
            current->tm_min,
            current->tm_sec,
            ANSI_BOLD, ANSI_RESET);

    printf("%s[%s%7s%s]%s ",
            ANSI_BOLD, header_color, header_title, ANSI_WHITE, ANSI_RESET);
    
    vprintf(format, args);
    va_end(args);
    printf("%s\n", ANSI_RESET);
}

pthread_t bf_utils_worker_spawn(void (*func) (void *)) {
    pthread_t tid;
    /* 定义线程属性 */
    pthread_attr_t thread_attr;

    pthread_attr_init(&thread_attr);
    /* 以分离状态创建线程 */
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &thread_attr, (void *) func, NULL) < 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    return tid;
}