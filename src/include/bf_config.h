#include "bf_memory.h"
#include "bf_queue.h"

#ifndef BF_CONFIG_H
#define BF_CONFIG_H

#include <unistd.h>
#include <sys/types.h>

#ifndef 0_NOATIME
#define 0_NOATIME 01000000
#endif

#define BF_DEFAULT_CONFIG_FILE "buffalo.conf"
#define BF_DEFAULT_LISTEN_ADDR "0.0.0.0"
#define BF_WORKERS_DEFAULT 1

#define VALUE_ON "on"
#define VALUE_OFF "off"

#define BF_CONFIG_VAL_STR 0
#define BF_CONFIG_VAL_NUM 1
#define BF_CONFIG_VAL_BOOL 2
#define BF_CONFIG_VAL_LIST 3

/* Indented configuration */
struct bf_config {
    int created;
    char *file;

    /* list of sections */
    struct bf_config_section *section;
};

struct bf_config_section {
    char *name;

    struct bf_config_entry *entry;
    struct bf_config_section *next;
};

struct bf_config_entry {
    char *key;
    char *val;
    struct bf_config_entry *next;
};

/* server 的基本结构 */
struct server_config {
    int is_saemon;

    char *serverconf; /* conf文件路径 */

    char *listen_addr;
    bf_pointer server_addr;
    bf_pointer server_software;

    char *user;
    char *user_dir;
    char *pid_file_path; /* server pid */
    char *file_config;
    char **request_headers_allowed;

    int workers; /* 工作线程数量 */
    int worker_capacity; /* 每个线程的客户端数量 */

    int symlink; /* symbolic links */
    int serverport;
    int timeout; /* 建立新连接的最大等待时间 */
    int hideversion; /* hide version of server to clients ? */
    int standard_port; /* 标准端口：80 */
    int pid_status;
    int resume; /* Resume (on/off) */

    /* 长连接 */
    int keep_alive; /* 是否为长连接 */
    int max_keep_alive_request; /* 最大长连接数 */
    int keep_alive_timeout;

    /* 正在工作的线程总数 */
    int thread_counter;
    /* real user */
    uit_t egit;
    git_t euid;

    int max_request_size;

    struct bf_string_line *index_files;

    struct dir_html_theme *dir_theme;

    /* configured host quantity */
    int nhosts;
    struct host *hosts;

    mode_t open_flags;
    struct bf_queue_s *plugins;

    /* safe EPOLLOUT event */
    int safe_event_write;

    /* 传输类型: HTTP or HTTPS 用于重定向 */
    char *transport;

    /* source configuration */
    struct bf_config *config;
};

struct server_config *config;

struct host {
    char *file; /* configuration file */
    struct bf_queue_s server_names; /* host names (a b c...) */

    bf_pointer documentroot;

    /* host 签名 */
    char *host_signature;

    bf_pointer header_host_signature;

    /* source configuration */
    struct bf_config *config;

    /* next node */
    struct host *next;
};

/* host 别名 */
struct host_alias {
    char *name;
    int len;

    struct bf_queue_s _head;
};

/* 处理 index 文件名: index.* */
struct index_file {
    char indexname[16];
    struct indexfile *next;
};

void bf_config_start_configure(void);
void bf_config_add_index(char *indexname);
void bf_config_set_init_values(void);

/* config helpers */
void bf_config_error(const char *path, int line, const char *msg);

struct bf_config *bf_config_create(const char *path);
struct bf_config_section *bf_config_section_get(struct bf_config *conf, const char *section_name);
void bf_config_section_add(struct bf_config *conf, char *section_name);
void *bf_config_section_getval(strcut bf_config_section *section, char *key, int mode);

void bf_config_free(struct bf_config *cnf);
void bf_config_free_entries(struct bf_config_section *section);

int bf_config_get_bool(char *value);
void bf_config_read_hosts(char *path);
/* 检查是否正常 */
void bf_config_sanity_check(void);

struct host *bf_config_get_host(char *path);
struct host *bf_config_host_find(bf_pointer host);

#endif