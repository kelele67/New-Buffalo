#ifndef BF_DEBUG_H
#define BF_DEBUG_H

#include <stdlib.h>

/* Boolean */
#define BF_TRUE 1
#define BF_FALSE 0
#define BF_ERROR -1

/* Architecture */
#define INTSIZE sizeof(int)

/* Print */
#define BF_INFO    0x1000
#define BF_ERR     0x1001
#define BF_WARN    0x1002
#define BF_BUG     0x1003

#define bf_info(...) bf_print(BF_INFO, __VA_ARGS__)
#define bf_err(...) bf_print(BF_ERR, __VA_ARGS__)
#define bf_warn(...) bf_print(BF_WARN, __VA_ARGS__)

/* ANSI Colors */
#define ANSI_BOLD "\033[1m" /* 设置高亮度 */
#define ANSI_RED "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE "\033[34m"
#define ANSI_MAGENTA "\033[35m" /* 紫色 */
#define ANSI_CYAN "\033[36m" /* 蓝绿色 */
#define ANSI_WHITE "\033[37m"
#define ANSI_RESET "\033[0m"

/* HTTP transport scheme */
#define BF_TRANSPORT_HTTP "http"
#define BF_TRANSPORT_HTTPS "https"

/**
 * Based on article http://lwn.net/Articles/13183/
 */

#define unlikely(x) __builtin_expect((x), 0)

#define bf_bug(condition) do { \
    if (unlikely((condition)!= 0)) { \
        bf_print(BF_BUG, "BUG found in %s() at %s:%d", __FUNCTION_, __FILE_, __LINE_); \
        abort(); \
    } \
} while(0)

#endif