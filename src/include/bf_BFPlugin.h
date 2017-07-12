#ifndef BUFFALO_PLUGIN_H
#define BUFFALO_PLUGIN_H

#include "bf_plugin.h"
#include "bf_queue.h"
#include "bf_http.h"
#include "bf_file.h"
#include "bf_socket.h"
#include "bf_debug.h"

/* 全局变量 */
struct plugin_api *bf_api;
struct plugin_info _plugin_info;

bf_plugin_key_t _bfp_data;

#define BUFFALO_PLUGIN(a, b, c, d) \
    struct plugin_info _plugin_info = {a, b, c, d}

#ifdef TRACE
#define PLUGIN_TRACE(...) \
    bf_api->trace(_plugin_info.shortname, \
                  BF_TRACE_PLUGIN, \
                  __FUNCTION__, \
                  __FILE__, \
                  __LINE__, \
                  __VA_ARGS__)
#else
#define PLUGIN_TRACE(...) do {} while (0)
#endif

/* 重新定义 message 宏 */

#undef bf_info
#define bf_info(...) bf_api->_error(BF_INFO, __VA_ARGS__)

#undef bf_err
#define bf_err(...) bf_api->_error(BF_ERR, __VA_ARGS__)

#undef bf_warn
#define bf_warn(...) bf_api->_error(BF_WARN, __VA_ARGS__)

#undef bf_bug
#define bf_bug(condition) dp { \
    if (ulikely((condition) != 0)) { \
        bf_api->_error(BF_BUG, "[%s] Bug found in %s() ar %s:%d", \
                       _plugin_info.shortname, __FUNCTION__, __FILE__, __LINE__); \
        abort(); \
    } \
} while (0)

#endif