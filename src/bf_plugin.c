#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h> // 使用Linux动态链接库
#include <err.h>

#include "include/bf_connection.h"
#include "include/bf_request.h"
#include "include/bf_utils.h"
#include "include/bf_file.h"
#include "include/bf_http.h"
#include "include/bf_timer.h"
#include "include/bf_plugin.h"
#include "include/bf_debug.h"

static int bf_plugin_event_set_list(struct bf_queue_s *list) {
	return pthread_setspecific(bf_plugin_event_k, (void *) list);
}

static struct bf_queue_s *bf_plugin_event_get_list() {
	return pthread_setspecific(bf_plugin_event_k);
}

// LINUX下动态链接库的使用
void *bf_plugin_load(char *path) {
	void *handle;

	// 该函数将打开一个新库，并把它装入内存
	// Apache Web 服务器利用这个函数在运行过程中加载模块，这为它提供了额外的能力
	// 这种机制使得在系统中添加或者删除一个模块时，都 不需要重新编译了
	handle = dlopen(path, PTLD_LAZY); // 设置的是 RTLD_LAZY，则在需要的时候才计算库的依赖性
	if (!handle) {
		bf_warn("dlopen() %s", dlerror());
	}

	return handle;
}

void *bf_plugin_load_symbol(void *handler, const char *symbol) {
	char *err;
	void *s;

	dlerror();
	/* 返回符号对应的地址 */
	/* 获取函数地址，也可以获取变量地址 */
	s = dlsym(handler, symbol);
	if ((err == dlerror())!= NULL) {
		return NULL;
	}

	return s;
}

void bf_plugin_register_stagemap_add(struct plugin_stagem **stm, struct plugin *p) {
	struct plugin_stagem *list, *_new;

	_new = bf_calloc(sizeof(struct plugin_stagem));
	_new->p = p;
	_new->next = NULL;

	if (!*stm) {
		*stm = new;
		return;
	}

	list = *stm;

	while (list->next) {
		list = list->next;
	}

	list->next = _new;
}

void nf_plugin_register_stagemap(struct plugin *p) {
    /* 插件的状态 */
    if (p->hooks & BF_PLUGIN_STAGE_10) {
        bf_plugin_register_stagemap_add(&plg_stagemap->stage_10, p);
    }

    if (p->hooks & BF_PLUGIN_STAGE_20) {
        bf_plugin_register_stagemap_add(&plg_stagemap->stage_20, p);
    }

    if (p->hooks & BF_PLUGIN_STAGE_30) {
        bf_plugin_register_stagemap_add(&plg_stagemap->stage_30, p);
    }

    if (p->hooks & BF_PLUGIN_STAGE_40) {
        bf_plugin_register_stagemap_add(&plg_stagemap->stage_40, p);
    }

    if (p->hooks & BF_PLUGIN_STAGE_50) {
        bf_plugin_register_stagemap_add(&plg_stagemap->stage_50, p);
    }
}

/* 分配插件内存 */
struct plugin *bf_plugin_alloc(void *handler, char *path)
{
    struct plugin *p;
    struct plugin_info *info;

    p = bf_calloc(sizeof(struct plugin));
    info = (struct plugin_info *) bf_plugin_load_symbol(handler, "_plugin_info");

    if (!info) {
        bf_warn("Plugin '%s' is not registering properly", path);
        return NULL;
    }

    p->shortname = (char *) (*info).shortname;
    p->name = (char *) (*info).name;
    p->version = (char *) (*info).version;
    p->hooks = (unsigned int) (*info).hooks;

    p->path = bf_string_dup(path);
    p->handler = handler;

    p->init = (int (*)()) bf_plugin_load_symbol(handler, "_bfp_init");
    p->exit = (int (*)()) bf_plugin_load_symbol(handler, "_bfp_exit");

    /* Core hooks */
    p->core.prctx = (int (*)()) bf_plugin_load_symbol(handler,
                                                      "_bfp_core_prctx");
    p->core.thctx = (int (*)()) bf_plugin_load_symbol(handler,
                                                      "_bfp_core_thctx");

    /* Stage hooks */
    p->stage.s10 = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_stage_10");

    p->stage.s20 = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_stage_20");

    p->stage.s30 = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_stage_30");

    p->stage.s40 = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_stage_40");

    p->stage.s50 = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_stage_50");

    /* Network I/O hooks */
    p->net_io.accept = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_accept");

    p->net_io.read = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_read");

    p->net_io.write = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_write");

    p->net_io.writev = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_writev");

    p->net_io.close = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_close");

    p->net_io.connect = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_connect");

    p->net_io.send_file = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_send_file");

    p->net_io.create_socket = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_create_socket");

    p->net_io.bind = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_bind");

    p->net_io.server = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_network_io_server");

    /* Thread key */
    p->thread_key = (pthread_key_t *) bf_plugin_load_symbol(handler, 
                                                            "_bfp_data");

    /* Event handlers hooks */
    p->event_read = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_event_read");

    p->event_write = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_event_write");

    p->event_error = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_event_error");

    p->event_close = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_event_close");

    p->event_timeout = (int (*)())
        bf_plugin_load_symbol(handler, "_bfp_event_timeout");

    return p;
}

/**
 * 注册插件并把符号放在插件list结点上
 */
struct plugin *bf_plugin_register(struct plugin *p)
{
    if (!p->name || !p->version || !p->hooks) {
        BF_TRACE("Plugin must define name, version and hooks. Check: %s", p->path);
        bf_plugin_free(p);
        return NULL;
    }

    if (!p->init || !p->exit) {
        BF_TRACE("Plugin must define hooks 'init' and 'exit'");
        bf_plugin_free(p);
        return NULL;
    }

    /* NETWORK_IO 插件 */
    if (p->hooks & BF_PLUGIN_NETWORK_IO) {
        /* 调用是否合法 */
        if (!p->net_io.accept || !p->net_io.read || !p->net_io.write ||
            !p->net_io.writev || !p->net_io.close || !p->net_io.connect ||
            !p->net_io.send_file || !p->net_io.create_socket || !p->net_io.bind ||
            !p->net_io.server ) {

            BF_TRACE("Networking IO plugin incomplete: %s", p->path);
            BF_TRACE("Mapped Functions\naccept : %p\nread : %p\n\
write : %p\nwritev: %p\nclose : %p\nconnect : %p\nsendfile : %p\n\
create socket : %p\nbind : %p\nserver : %p",
                     p->net_io.accept,
                     p->net_io.read,
                     p->net_io.write,
                     p->net_io.writev,
                     p->net_io.close,
                     p->net_io.connect,
                     p->net_io.send_file,
                     p->net_io.create_socket,
                     p->net_io.bind,
                     p->net_io.server);

            bf_plugin_free(p);
            return NULL;
        }

        /* 只允许有一个 NETWORK_IO 插件 */
        if (!plg_netiomap) {
            plg_netiomap = &p->net_io;
        }
        else {
            bf_err("Error: Loading more than one Network IO Plugin: %s", p->path);
            exit(EXIT_FAILURE);
        }
    }

    /* 把插件添加到list尾部 */
    bf_queue_add(&p->_head, config->plugins);

    /* 注册插件状态表 */
    bf_plugin_register_stagemap(p);
    return p;
}

void bf_plugin_unregister(struct plugin *p) {
	bf_queue_del(&p->_head);
	bf_plugin_free(p);
}

void bf_plugin_free(struct plugin *p) {
	bf_free(p->path);
	bf_free(p);
	p = NULL;
}

void bf_plugin_init() {
	int ret;
	char *path;
	char *plugin_confdir = 0;
	void *handle;
	unsigned long len;
	struct plugin *p;
	struct plugin_api *api;
	struct bf_config *cnf;
	struct bf_config_section *section;
	struct bf_config_entry *entry;

	api = bf_calloc(sizeof(struct plugin_api));
	plg_stagemap = bf_calloc(sizeof(struct plugin_stagemap));
	plg_netiomap = NULL;

	/* 建立并连接list */
	api->config = config;
	api->sched_list = &sched_list;

	/* API 插件功能 */

	/* 错误处理 */
	api->error = (void *) bf_print;
    /* HTTP callbacks */
    api->http_request_end = (void *) bf_plugin_http_request_end;

    /* Memory callbacks */
    api->pointer_set = (void *) bf_pointer_set;
    api->pointer_print = (void *) bf_pointer_print;
    api->pointer_to_buf = (void *) bf_pointer_to_buf;
    api->plugin_load_symbol = (void *) bf_plugin_load_symbol;
    api->alloc = (void *) bf_alloc;
    api->calloc = (void *) bf_calloc;
    api->free = (void *) bf_free;

    /* String Callbacks */
    api->str_build = (void *) bf_string_build;
    api->str_dup = (void *) bf_string_dup;
    api->str_search = (void *) bf_string_search;
    api->str_search_n = (void *) bf_string_search_n;
    api->str_copy_substr = (void *) bf_string_copy_substr;
    api->str_itop = (void *) bf_string_itop;
    api->str_split_line = (void *) bf_string_split_line;

    /* File Callbacks */
    api->file_to_buffer = (void *) bf_file_to_buffer;
    api->file_get_info = (void *) bf_file_get_info;

    /* HTTP Callbacks */
    api->header_send = (void *) bf_header_send;
    api->header_add = bf_plugin_header_add;
    api->header_get = bf_request_header_get;
    api->header_set_http_status = (void *) bf_header_set_http_status;
    
    /* IOV callbacks */
    api->iov_create = (void *) bf_iov_create;
    api->iov_free = (void *) bf_iov_free;
    api->iov_add_entry = (void *) bf_iov_add_entry;
    api->iov_set_entry = (void *) bf_iov_set_entry;
    api->iov_send = (void *) bf_iov_send;
    api->iov_print = (void *) bf_iov_print;

    /* EPoll callbacks */
    api->epoll_create = (void *) bf_epoll_create;
    api->epoll_init = (void *) bf_epoll_init;
    api->epoll_add = (void *) bf_epoll_add;
    api->epoll_del = (void *) bf_epoll_del;
    api->epoll_change_mode = (void *) bf_epoll_change_mode;

    /* Socket callbacks */
    api->socket_cork_flag = (void *) bf_socket_set_cork_flag;
    api->socket_connect = (void *) bf_socket_connect;
    api->socket_reset = (void *) bf_socket_reset;
    api->socket_set_tcp_nodelay = (void *) bf_socket_set_tcp_nodelay;
    api->socket_set_nonblocking = (void *) bf_socket_set_nonblocking;
    api->socket_create = (void *) bf_socket_create;
    api->socket_close = (void *) bf_socket_close;
    api->socket_sendv = (void *) bf_socket_sendv;
    api->socket_send = (void *) bf_socket_send;
    api->socket_read = (void *) bf_socket_read;
    api->socket_send_file = (void *) bf_socket_send_file;
    
    /* Config Callbacks */
    api->config_create = (void *) bf_config_create;
    api->config_free = (void *) bf_config_free;
    api->config_section_get = (void *) bf_config_section_get;
    api->config_section_getval = (void *) bf_config_section_getval;

    /* Scheduler and Event callbacks */
    api->sched_get_connection = (void *) bf_sched_get_connection;
    api->sched_remove_client = (void *) bf_plugin_sched_remove_client;

    api->event_add = (void *) bf_plugin_event_add;
    api->event_del = (void *) bf_plugin_event_del;
    api->event_socket_change_mode = (void *) bf_plugin_event_socket_change_mode;
    
    /* Worker functions */
    api->worker_spawn = (void *) bf_utils_worker_spawn;

    /* Some useful functions =) */
    api->sys_get_somaxconn = (void *) bf_utils_get_somaxconn;

    /* Time functions */
    api->time_unix = (void *) bf_plugin_time_now_unix;
    api->time_human = (void *) bf_plugin_time_now_human;

#ifdef TRACE
    api->trace = (void *) bf_utils_trace;
    api->errno_print = (void *) bf_utils_print_errno;
#endif

    /* Read configuration file */
    path = bf_calloc(1024);
    snprintf(path, 1024, "%s/%s", config->serverconf, BF_PLUGIN_LOAD);
    cnf = bf_config_create(path);
    
    if (!cnf) {
        bf_err("Plugins configuration file could not be readed");
        bf_free(path);
        exit(EXIT_FAILURE);
    }

    /* Read section 'PLUGINS' */
    section = bf_config_section_get(cnf, "PLUGINS");

    /* Read key entries */
    entry = section->entry;
    while (entry) {
        if (strcasecmp(entry->key, "Load") == 0) {
            handle = bf_plugin_load(entry->val);

            if (!handle) {
                bf_warn("Invalid plugin '%s'", entry->val);
                entry = entry->next;
                continue;
            }

            p = bf_plugin_alloc(handle, entry->val);
            if (!p) {
                bf_warn("Plugin error: %s\n", entry->val);
                dlclose(handle);
                entry = entry->next;
                continue;
            }

            /* 创建插件的配置路径 */
            bf_string_build(&plugin_confdir,
                            &len,
                            "%s/plugins/%s/",
                            config->serverconf, p->shortname);

            BF_TRACE("Load Plugin '%s@%s'", p->shortname, p->path);
            
            /* 初始化插件 */
            ret = p->init(&api, plugin_confdir);
            if (ret < 0) {
                /* 不注册插件 */
                BF_TRACE("Unregister plugin '%s'", p->shortname);

                bf_plugin_free(p);
                entry = entry->next;
                continue;
            }

            bf_free(plugin_confdir);
            plugin_confdir = NULL;

            /* 如果一切正常，注册插件 */
            bf_plugin_register(p);
        }
        entry = entry->next;
    }

    if (!plg_netiomap) {
        bf_err("No network plugin loaded >:|");
        exit(EXIT_FAILURE);
    }

    api->plugins = config->plugins;

    /* Look for plugins thread key data */
    bf_plugin_preworker_calls();
    bf_free(path);
}

void bf_plugin_exit_all()
{
    struct plugin *node;
    struct bf_queue_s *head;

    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        node->exit();
    }
}

int bf_plugin_stage_run(unsigned int hook,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_session *cs, struct session_request *sr)
{
    int ret;
    struct plugin_stagem *stm;

    /* Connection just accept(ed) not assigned to worker thread */
    if (hook & BF_PLUGIN_STAGE_10) {
        stm = plg_stagemap->stage_10;
        while (stm) {
            BF_TRACE("[%s] STAGE 10", stm->p->shortname);

            ret = stm->p->stage.s10(socket, conx);
            switch (ret) {
            case BF_PLUGIN_RET_CLOSE_CONX:
                BF_TRACE("return BF_PLUGIN_RET_CLOSE_CONX");
                return BF_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
    }

    /* The HTTP Request stream has been just received */
    if (hook & BF_PLUGIN_STAGE_20) {
        stm = plg_stagemap->stage_20;
        while (stm) {
            BF_TRACE("[%s] STAGE 20", stm->p->shortname);

            ret = stm->p->stage.s20(cs, sr);
            switch (ret) {
            case BF_PLUGIN_RET_CLOSE_CONX:
                BF_TRACE("return BF_PLUGIN_RET_CLOSE_CONX");

                return BF_PLUGIN_RET_CLOSE_CONX;
            }

            stm = stm->next;
        }
    }

    /* The plugin acts like an Object handler, it will take care of the 
     * request, it decides what to do with the request 
     */
    if (hook & BF_PLUGIN_STAGE_30) {
        /* The request just arrived and is required to check who can
         * handle it */
        if (!sr->handled_by){
            stm = plg_stagemap->stage_30;
            while (stm) {
                /* Call stage */
                BF_TRACE("[%s] STAGE 30", stm->p->shortname);
                ret = stm->p->stage.s30(stm->p, cs, sr);

                switch (ret) {
                case BF_PLUGIN_RET_NOT_ME:
                    break;
                case BF_PLUGIN_RET_END:
                    return BF_PLUGIN_RET_END;
                case BF_PLUGIN_RET_CLOSE_CONX:
                    return BF_PLUGIN_RET_CLOSE_CONX;
                default:
                    bf_err("Plugin '%s' returns invalid value %i",
                           stm->p->shortname, ret);
                    exit(EXIT_FAILURE);
                }
                
                stm = stm->next;
            }
        }
    }

    /* The request has ended, the content has been served */
    if (hook & BF_PLUGIN_STAGE_40) {
        stm = plg_stagemap->stage_40;
        while (stm) {
            BF_TRACE("[%s] STAGE 40", stm->p->shortname);

            ret = stm->p->stage.s40(cs, sr);
            stm = stm->next;
        }
    }

    /* The request has ended, the content has been served */
    if (hook & BF_PLUGIN_STAGE_50) {
        stm = plg_stagemap->stage_50;
        while (stm) {
            BF_TRACE("[%s] STAGE 50", stm->p->shortname);

            ret = stm->p->stage.s50(socket);
            switch (ret) {
            case BF_PLUGIN_RET_NOT_ME:
                break;
            case BF_PLUGIN_RET_CONTINUE:
                return BF_PLUGIN_RET_CONTINUE;
            }
            stm = stm->next;
        }
    }

    return -1;
}

void bf_plugin_request_handler_add(struct session_request *sr, struct plugin *p)
{
    if (!sr->handled_by) {
        sr->handled_by = p;
        return;
    }
}

void bf_plugin_request_handler_del(struct session_request *sr, struct plugin *p)
{
    if (!sr->handled_by) {
        return;
    }

    bf_free(sr->handled_by);
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void bf_plugin_core_process()
{
    struct plugin *node;
    struct bf_queue_s *head;

    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        
        /* Init plugin */
        if (node->core.prctx) {
            node->core.prctx(config);
        }
    }
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context
 */
void bf_plugin_core_thread()
{

    struct plugin *node;
    struct bf_queue_s *head;

    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);

        /* Init plugin thread context */
        if (node->core.thctx) {
            node->core.thctx();
        }
    }
}

/* This function is called by Monkey *outside* of the
 * thread context for plugins, so here's the right
 * place to set pthread keys or similar
 */
void bf_plugin_preworker_calls()
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;

    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);

        /* Init pthread keys */
        if (node->thread_key) {
            BF_TRACE("[%s] Set thread key", node->shortname);

            ret = pthread_key_create(node->thread_key, NULL);
            if (ret != 0) {
                bf_err("Plugin Error: could not create key for %s",
                       node->shortname);
            }
        }
    }
}

int bf_plugin_event_del(int socket)
{
    struct bf_queue_s *head, *list, *temp;
    struct plugin_event *node;

    BF_TRACE("[FD %i] Plugin delete event", socket);

    if (socket <= 0) {
        return -1;
    }

    list = bf_plugin_event_get_list();
    bf_queue_foreach_safe(head, temp, list) {
        node = bf_queue_entry(head, struct plugin_event, _head);
        if (node->socket == socket) {
            bf_queue_del(head);
            bf_free(node);
            bf_plugin_event_set_list(list);
            return 0;
        }
    }

    BF_TRACE("[FD %i] not found, could not delete event node :/");
    return -1;
}

int bf_plugin_event_add(int socket, int mode,
                        struct plugin *handler,
                        struct client_session *cs,
                        struct session_request *sr)
{
    struct sched_list_node *sched;
    struct plugin_event *event;

    struct bf_queue_s *list;
    
    sched = bf_sched_get_thread_conf();

    if (sched && handler && cs && sr) {
        /* Event node (this list exist at thread level */
        event = bf_alloc(sizeof(struct plugin_event));
        event->socket = socket;
        event->handler = handler;
        event->cs = cs;
        event->sr = sr;
        
        /* Get thread event list */
        list = bf_plugin_event_get_list();
        bf_queue_add(&event->_head, list);
        bf_plugin_event_set_list(list);
    }

    /* The thread event info has been registered, now we need
       to register the socket involved to the thread epoll array */
    bf_epoll_add(sched->epoll_fd, socket,
                 mode, BF_EPOLL_BEHAVIOR_DEFAULT);
    return 0;
}

int bf_plugin_http_request_end(int socket)
{
    int ret;

    BF_TRACE("[FD %i] PLUGIN HTTP REQUEST END", socket);

    ret = bf_http_request_end(socket);
    BF_TRACE(" ret = %i", ret);

    if (ret < 0) {
        return bf_conn_close(socket);
    }

    return 0;
}

int bf_plugin_event_socket_change_mode(int socket, int mode)
{
    struct sched_list_node *sched;

    sched = bf_sched_get_thread_conf();

    if (!sched) {
        return -1;
    }

    return bf_epoll_change_mode(sched->epoll_fd, socket, mode);
}

struct plugin_event *bf_plugin_event_get(int socket)
{
    struct bf_queue_s *head, *list;
    struct plugin_event *node;

    list = bf_plugin_event_get_list();

    /* 
     * In some cases this function is invoked from scheduler.c when a connection is
     * closed, on that moment there's no thread context so the returned list is NULL.
     */
    if (!list) {
        return NULL;
    }

    bf_queue_foreach(head, list) {
        node = bf_queue_entry(head, struct plugin_event, _head);
        if (node->socket == socket) {
            return node;
        }
    }

    return NULL;
}

void bf_plugin_event_init_list()
{
    struct bf_queue_s *list;

    list = bf_alloc(sizeof(struct bf_queue_s));
    bf_queue_init(list);

    bf_plugin_event_set_list(list);
}

/* Plugin epoll event handlers
 * ---------------------------
 * this functions are called by connection.c functions as bf_conn_read(),
 * bf_conn_write(),bf_conn_error(), bf_conn_close() and bf_conn_timeout().
 *
 * Return Values:
 * -------------
 *    BF_PLUGIN_RET_EVENT_NOT_ME: There's no plugin hook associated
 */

void bf_plugin_event_bad_return(const char *hook, int ret)
{
    bf_err("[%s] Not allowed return value %i", hook, ret);
}

int bf_plugin_event_check_return(const char *hook, int ret)
{
#ifdef TRACE
    BF_TRACE("Hook '%s' returned %i", hook, ret);
    switch(ret) {
    case BF_PLUGIN_RET_EVENT_NEXT:
        BF_TRACE("ret = BF_PLUGIN_RET_EVENT_NEXT");
        break;
    case BF_PLUGIN_RET_EVENT_OWNED:
        BF_TRACE("ret = BF_PLUGIN_RET_EVENT_OWNED");
        break;
    case BF_PLUGIN_RET_EVENT_CLOSE:
        BF_TRACE("ret = BF_PLUGIN_RET_EVENT_CLOSE");
        break;
    case BF_PLUGIN_RET_EVENT_CONTINUE:
        BF_TRACE("ret = BF_PLUGIN_RET_EVENT_CONTINUE");
        break;
    default:
        BF_TRACE("ret = UNKNOWN, bad monkey!, follow the spec! >:D");
    }
#endif

    switch(ret) {
    case BF_PLUGIN_RET_EVENT_NEXT:
    case BF_PLUGIN_RET_EVENT_OWNED:
    case BF_PLUGIN_RET_EVENT_CLOSE:
    case BF_PLUGIN_RET_EVENT_CONTINUE:
        return 0;
    default:
        bf_plugin_event_bad_return(hook, ret);
    }
    
    /* don't cry gcc :_( */
    return -1;
}

int bf_plugin_event_read(int socket)
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;
    struct plugin_event *event;

    BF_TRACE("[FD %i] Read Event", socket);

    /* 插件注册的socket */
    event = bf_plugin_event_get(socket);
    if (event) {
        if (event->handler->event_read) {
            BF_TRACE("[%s] plugin handler",  event->handler->name);

            ret = event->handler->event_read(socket);
            bf_plugin_event_check_return("read|handled_by", ret);
            return ret;
        }
    }

    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        if (node->event_read) {
            ret = node->event_read(socket);

            /* validate return value */
            bf_plugin_event_check_return("read", ret);
            if (ret == BF_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
    }

    return BF_PLUGIN_RET_EVENT_CONTINUE;
}

int bf_plugin_event_write(int socket)
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;
    struct plugin_event *event;

    BF_TRACE("[FD %i] Plugin event write", socket);

    event = bf_plugin_event_get(socket);
    if (event) {
        if (event->handler->event_write) {
            BF_TRACE(" event write handled by plugin");

            ret = event->handler->event_write(socket);
            bf_plugin_event_check_return("write|handled_by", ret);
            return ret;
        }
    }
    
    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        if (node->event_write) {
            ret = node->event_write(socket);

            /* validate return value */
            bf_plugin_event_check_return("write", ret);
            if (ret == BF_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
    }
    
    return BF_PLUGIN_RET_CONTINUE;
}

int bf_plugin_event_error(int socket)
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;
    struct plugin_event *event;

    BF_TRACE("[FD %i] Plugin event error", socket);

    event = bf_plugin_event_get(socket);
    if (event) {
        if (event->handler->event_error) {
            BF_TRACE(" event error handled by plugin");

            ret = event->handler->event_error(socket);
            bf_plugin_event_check_return("error|handled_by", ret);
            return ret;
        }
    }
    
    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        if (node->event_error) {
            ret = node->event_error(socket);

            /* validate return value */
            bf_plugin_event_check_return("error", ret);
            if (ret == BF_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
    }

    return BF_PLUGIN_RET_CONTINUE;
}

int bf_plugin_event_close(int socket)
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;
    struct plugin_event *event;

    BF_TRACE("[FD %i] Plugin event close", socket);

    event = bf_plugin_event_get(socket);
    if (event) {
        if (event->handler->event_close) {
            BF_TRACE(" event close handled by plugin");

            ret = event->handler->event_close(socket);
            bf_plugin_event_check_return("close|handled_by", ret);
            return ret;
        }
    }
    
    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        if (node->event_close) {
            ret = node->event_close(socket);

            /* validate return value */
            bf_plugin_event_check_return("close", ret);
            if (ret == BF_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
    }

    return BF_PLUGIN_RET_CONTINUE;
}

int bf_plugin_event_timeout(int socket)
{
    int ret;
    struct plugin *node;
    struct bf_queue_s *head;
    struct plugin_event *event;

    BF_TRACE("[FD %i] Plugin event timeout", socket);

    event = bf_plugin_event_get(socket);
    if (event) {
        if (event->handler->event_timeout) {
            BF_TRACE(" event close handled by plugin");

            ret = event->handler->event_timeout(socket);
            bf_plugin_event_check_return("timeout|handled_by", ret);
            return ret;
        }
    }
    
    bf_queue_foreach(head, config->plugins) {
        node = bf_queue_entry(head, struct plugin, _head);
        if (node->event_timeout) {
            ret = node->event_timeout(socket);

            /* validate return value */
            bf_plugin_event_check_return("timeout", ret);
            if (ret == BF_PLUGIN_RET_EVENT_NEXT) {
                continue;
            }
            else {
                return ret;
            }
        }
    }

    return BF_PLUGIN_RET_CONTINUE;
}

int bf_plugin_time_now_unix()
{
    return log_current_utime;
}

bf_pointer *bf_plugin_time_now_human()
{
    return &log_current_time;
}

int bf_plugin_sched_remove_client(int socket)
{
    struct sched_list_node *node;

    BF_TRACE("[FD %i] remove client", socket);

    node = bf_sched_get_thread_conf();
    return bf_sched_remove_client(node, socket);
}

int bf_plugin_header_add(struct session_request *sr, char *row, int len)
{
    bf_bug(!sr);
    bf_bug(!sr->headers);

    if (!sr->headers->_extra_rows) {
        /* 
         * We allocate space for:
         *   + 8 slots extra headers
         *   + 8 slots to be used with CRLF for every extra header
         *   + 2 slots for the ending CRLF
         * -------------------------------------------------------
         *    18 iov slots
         */
        sr->headers->_extra_rows = bf_iov_create(18, 0);
        bf_bug(!sr->headers->_extra_rows);
    }

    bf_iov_add_entry(sr->headers->_extra_rows, row, len, 
                     bf_iov_crlf, BF_IOV_NOT_FREE_BUF);
    return 0;
}