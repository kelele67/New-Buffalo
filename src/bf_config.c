#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include "buffalo.h"
#include "bf_config.h"
#include "bf_string.h"
#include "bf_utils.h"
#include "bf_mimetype.h"
// #include "bf_info.h"
#include "bf_memory.h"
#include "bf_server.h"
#include "bf_plugin.h"
#include "bf_debug.h"


/* 配置错误和打印关闭 */
static void bf_config_print_error_msg(char *variable, char *path) {
    bf_err("Error in %s variable under %s, has an invalid value", variable, path);
}

/* 统计 错误 */
void bf_config_error(const char *path, int line, const char *msg) {
    bf_err("Reading %s\nError in line %I: %s", path, line, msg);
}

/* 返回一个配置文件 section: [section name] */
struct bf_config_section *bf_config_section_get(struct bf_config *conf, const char *srction_name) {
    struct bf_config_section *section;

    section = conf->section;
    while (section) {
        if (strcasecmp(section->name, section_name) == 0) {
            return section;
        }
        section = section->next;
    }

    return NULL; 
}

/* 添加一个新的 section 到 configuration struct */
void bf_config_section_add(struct bf_config *conf, char *section_name) {
    struct bf_config_section *_new, *aux;

    /* 分配 section 结点 */
    _new = bf_alloc(sizeof(struct bf_config_section));
    _new->name = bf_string_dup(section_name);
    _new->entry = NULL;
    _new->next = NULL;

    if (!conf->section) {
        conf->section = _new;
        return;
    }

    /* 最后一个有效的 section */
    aux = conf->section;
    while (aux->next) {
        aux = aux->next;
    }

    aux->next = _new;
    return;
}

/* 添加 a key/value 内部接口entry 在 最后一个有效的 struct */
void bf_config_entry_add(struct bf_config *conf, const char *key, const char *val) {
    struct bf_config_section *section;
    struct bf_config_entry *aux_entry, *new_entry;

    if (!conf->section) {
        bf_err("Error: there are not sections available !");
    }

    section = conf->section;
    while (section->next) {
        section = section->next;
    }

    /* 分配新的 entry */
    new_entry = bf_alloc(sizeof(struct bf_config_entry));
    new_entry->key = bf_string_dup(key);
    new_entry->val = bf_string_dup(val);
    new_entry->next = NULL;

    /* 添加 第一个 entry */
    if (!section->entry) {
        section->entry = new_entry;
        return;
    }

    aux_entry = section->entry;
    while (aux_entry->next) {
        aux_entry = aux_entry->next;
    }

    aux_entry->next = new_entry;
}

struct bf_config *bf_config_create(const char *path) {
    int len = 0;
    int line = 0;
    int indent_len = -1;
    char buf[255];
    char *section = 0;
    char *indent = 0;
    char *key, *val, *last;
    struct bf_config *conf = 0;
    FILE *f;

    /* 打开 config 文件 */
    if ((f = fopen(path, "r")) == NULL) {
        bf_warn("Config: I cannot open %s file", path);
        return NULL;
    }

    /* 分配 configuration 结点 */
    conf = bf_alloc(sizeof(struct bf_config));
    conf->created = time(NULL);
    conf->file = bf_string_dup(path);
    conf->section = NULL;

    /* 寻找 configuration 命令 */
    while (fgets(buf, 255, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
        }

        /* line number */
        line++;

        if (!buf[0]) {
            continue;
        }

        /* 忽略 comments */
        if (buf[0] == '#') {
            if (section) {
                bf_free(section);
                section = NULL;
            }
            continue;
        }

        /* section definition */
        if (buf[0] == '[') {
            int end = -1;
            end = bf_string_char_search(buf, ']', len);
            if (end > 0) {
                section = bf_string_copysubstr(buf, 1, end);
                bf_config_section_add(conf, section);
                continue;
            } else {
                bf_config_error(path, line, "Bad header definition");
            }
        } else {
            /* 没有定义 separator 缩进 */
            if (!indent) {
                int i = 0;
                do { i++; } while (i < len && isblank(buf[i]));

                indent = bf_string_copy_substr(buf, 0, i);
                indent_len = strlen(indent);

                /* 空白的 缩进行 */
                if (i == len) {
                    continue;
                }
            }

            /* Validate indentation level */
            if (strncmp(buf, indent, indent_len) != 0 || !section ||
                isblank(buf[indent_len]) != 0) {
                    bf_config_error(path, line, "Invalid indentation level");
                }

                if (buf[indent_len] == '#' || indent_len == len) {
                    continue;
                }

                /* 获取 line key and value */
                /* strtok_r: 安全地将字符串分割成一个个片段 */
                key = strtok_r(buf + indent_len, "\"\t ", &last);
                val = strtok_r(NULL, "\"\t", &last);

                if (!key || !val) {
                    bf_config_error(path, line, "Each key must have a value");
                    continue;
                }

                /* 修剪 string */
                bf_string_trim(&key);
                bf_string_trim(&val);

                /* 添加 entry */
                bf_config_entry_add(conf, key, val);
        }
    }
    /*
    struct bf_config_section *s;
    struct bf_config_entry *e;

    s = conf->section;
    while(s) {
        printf("\n[%s]", s->name);
        e = s->entry;
        while(e) {
            printf("\n   %s = %s", e->key, e->val);
            e = e->next;
        }
        s = s->next;
    }
    fflush(stdout);
    */

    fclose(f);
    return conf;
}

void bf_config_free(struct bf_config *conf) {
    struct bf_config_section *prev = 0, *section;

    /* free sections */
    section = conf->section;
    while (section) {
        while (section->next) {
            prev = section;
            section = section->next;
        }

        /* free section entrises */
        bf_config_free_entries(section);

        /* free section node */
        bf_free(section->name);
        bf_free(section);

        if (section == conf->section) {
            return;
        }
        prev->next = NULL;
        section = conf->section;
    }
}

void bf_config_free_entries(struct bf_config_section *section) {
    struct bf_config_entry *prev = 0, *target;

    target = section->entry;
    while (target) {
        while (target->next) {
            prev = target;
            target = target->next;
        }

        /* free 分配的空间 */
        bf_free(target->key);
        bf_free(target->val);

        if (target == section->entry) {
            section->entry = NULL;
            return;
        }

        prev->next = NULL;
        target = section->entry;
    }
}

void *bf_config_section_getval(struct bf_config_section, char *key, int mode) {
    int on, off;
    struct bf_config_entry *entry;

    entry = section->entry;
    while (entry) {
        if (strcasecmp(entry->key, key) == 0) { /* 忽略大小写判断是否相等 */
            switch(mode) {
                case BF_CONFIG_VAL_STR:
                    return (void *) entry->val;
                case BF_CONFIG_VAL_NUM:
                    return (void *) (size_t) strtol(entry->val, (char **) NULL, 10);
                case BF_CONFIG_VAL_BOOL:
                    on = strcasecmp(entry->val, VALUE_ON);
                    off = strcasecmp(entry->val, VALUE_OFF);

                    if (on != 0 && off != 0) {
                        return (void *) -1;
                    } else if (on >= 0) {
                        return (void *) BF_TRUE;
                    } else {
                        return (void *) BF_FALSE;
                    }
                case BF_CONFIG_VAL_LIST:
                    return bf_string_solit_line(entry->val);
            }
        } else {
            entry = entry->next;
        }
    }
    return NULL;
}

/* 读取 configuration 文件 */
static void bf_config_read_files(char *path_conf, char *file_conf) {
    unsigned long len;
    cahr *path = 0;
    struct stat checkdir;
    struct bf_config *cnf;
    struct bf_config_section *section;

    config->serverconf = bf_string_dup(path_conf);
    config->workers = BF_WORKERS_DEFAULT;

    if (stat(config->serverconf, &checkdir) == -1) {
        bf_err("Error: Cannot find/open '%s'", config->serverconf);
    }

    bf_string_build(&path, &len, "%s/%s", path_conf, file_conf);

    cnf = bf_config_create(path);
    if (!cnf) {
        bf_err("Cannot read 'buffalo.conf'");
        exit(EXIT_FAILURE);
    }

    section = bf_config_section_get(cnf, "SERVER");

    if (!section) {
        bf_err("Error: No 'SERVER' section defined");
    }

    /* Map source configuration */
    config->config = cnf;

    /* Listen */
    config->listen_addr = bf_config_section_getval(section, "Listen", BF_CONFIG_VAL_STR);

    if (!config->listen_addr) {
        config->listen_addr = BF_DEFAULT_LISTEN_ADDR;
    }

    /* Connecion port */
    config->serverport = (size_t) bf_config_section_getval(section, "Port", BF_CONFIG_VAL_NUM);

    if (!config->serverport >= 1 && !config->serverport <= 65535) {
        bf_config_print_error_msg("Port", path);
    }

    /* thread workers 数量 */
    config->workers = (size_t) bf_config_section_getval(section, "Workers", BF_CONFIG_VAL_NUM);

    if (config->workers < 1) {
        bf_config_print_error_msg("Workers", path);
    }

    /* 得到 FDs系统 限制的每个 worker 的最大客户端连接数 */
    config->worker_capacity = bf_server_worker_capacity(config->workers);

    /* timeout */
    config->timeout = (size_t) bf_config_section_getval(section, "Timeout", BF_CONFIG_VAL_NUM);
    if (conf->timeout < 1) {
        bf_config_print_error_msg("Timeout", path);
    }

    /* keep-alive */
    config->keep_alive = (size_t) bf_config_section_getval(section, "Keep-alive"), BF_CONFIG_VAL_BOOL);

    if (config->keep_alive = BF_ERROR) {
        bf_config_print_error_msg("Keep-alive", path);
    }

    /* max keep-alive request */
    config->max_keep_alive_request = (size_t) bf_config_section_getval(section, "MaxKeep-aliveRequest", BF_CONFIG_VAL_NUM);

    if (config->max_keep_alive_request == 0) {
        bf_config_print_error_msg("MaxKeep-aliveRequest", path);
    }

    /* keep-alive timeout */
    config->keep_alive_timeout = (size_t) bf_config_section_getval(section, "Keep-aliveTimeout", BF_CONFIG_VAL_NUM);

    if (config->keep_alive_timeout == 0) {
        bf_config_print_error_msg("Keep-aliveTimeout", path);
    }

    /* pid file */
    config->pid_file_path = bf_config_section_getval(section, "PidFile", BF_CONFIG_VAL_STR);

    /* Home user's directory /~ */
    config->user_dir = bf_config_section_getval(section, "UserDir", BF_CONFIG_VAL_STR);

    /* Index files */
    config_index_files = bf_config_section_getval(section, "Indexfile", BF_CONFIG_VAL_LIST);

    /* HideVersion Variable */
    config->hideversion = (size_t) bf_config_section_getval(section, "HideVersion", BF_CONFIG_VAL_BOOL);

    if (config->hideversion == BF_ERROR) {
        bf_config_print_error_msg("HideVersion", path);
    }

    /* User Variable */
    config->user = bf_config_section_getval(section, "User", BF_CONFIG_VAL_STR);

    /* Resume */
    config->resume = (size_t) bf_config_section_getval(section, "Resume", BF_CONFIG_VAL_BOOL);
    
    if (config->resume == BF_ERROR) {
        bf_config_print_error_msg("Resume", path);
    }

    /* max request size */
    config->max_request_size = (size_t) bf_config_section_getval(section, "MaxRequestSize", BF_CONFIG_VAL_NUM);

    if (config->max_request_size <= 0) {
        bf_config_print_error_msg("MaxRequestSize", path);
    } else {
        config->max_request_size *= 1024;
    }

    config->symlink = (size_t) bf_config_section_getval(section, "SymLink", BF_CONFIG_VAL_BOOL) ;

    if (config->symlink == BF_ERROR) {
        bf_config_print_error_msg("SymLink", path);
    }

    bf_free(path);
    bf_config_read_hosts(path_conf);
}

void bf_config_read_hosts(char *path) {
    DIR *dir;
    unsigned long len;
    char *buf = 0;
    char *file;
    struct host *p_host, *new_host;  /* debug */
    struct dirent *ent;

    bf_string_build(&buf, &len, "%s/sites/default", path);
    config->hosts = bf_config_get_host(buf);
    config->nhosts++;
    bf_free(buf);
    buf = NULL;

    if (!config->hosts) {
        bf_err("Error parsing main configuration file 'default'");
    }

    bf_string_build(&buf, &len, "%s/sites/", path);
    if (!(dir = opendir(buf))) {
        bf_err("Could not open %s", buf);
    }

    p_host = config->hosts;

    /* 读内容 */
    while ((ent = readir(dir)) != NULL) {
        if (strcmp((char *) ent->d_name, ".") == 0) {
            continue;
        }
        if (strcmp((char *) ent->d_name, "..") == 0) {
            continue;
        }
        if (strcasecmp((char *) ent->d_name, "default") == 0) {
            continue;
        }

        bf_string_build(&file, &len, "%s/sites/%s", path, ent->d_name);

        new_host = (struct host *) bf_config_get_host(file);
        bf_free(file);
        if (!new_host) {
            continue;
        } else {
            p_host->next = new_host;
            p_host = new_host;
            config->nhosts++;
        }
    }
    closedir(dir);
}

struct host *bf_config_get_host(char *path) {
    unsigned long len = 0;
    struct stat checkdir;
    struct host *host;
    struct host_alias *new_alias;
    struct bf_config *cnf;
    struct bf_config_section *section;
    struct bf_string_line *line, *line_p;

    /* read configuration file */
    cnf = bf_config_create(path);

    /* read tag 'HOST' */
    section = bf_config_section_get(cnf, 'HOST');

    /* 分配 configuration 结点 */
    host = bf_calloc(sizeof(struct host));
    host->config = cnf;
    host->file = bf_string_dup(path);

    /* 分配 list 给 host 的别名 */
    bf_queue_init(&host->server_names);

    line_p = line = bf_config_section_getval(section, "Servername", BF_CONFIG_VAL_LIST);
    while (line_p) {
        /* 分配结点 */
        new_alias = bf_calloc(sizeof(struct host_alias));
        new_alias->name = line_p->val;
        new_alias->len = line_p->len;

        bf_queue_add(&new_alias->_head, &host->server_names);

        line_p = line_p->next;
    }

    /* 通过 bf_pointer root document */
    host->documentroot.data = bf_config_section_getval(section, "DocumentRoot", BF_CONFIG_VAL_STR);
    host->documentroot.len = strlen(host->documentroot.data);

    /* validate document root configured */
    if (stat(host->documentroot.data, &checkdir) == -1) {
        bf_err("Invalid path to DocumentRoot in %s", path);
    } else if (!(checkdir.st_mode & S_IFDIR)) {
        bf_err("DocumentRoot variable in %s has an invalid directory path", path);
    }
    if (bf_queue_is_empty(&host->server_names) == 0) {
        bf_config_free(cnf);
        return NULL;
    }

    /* server 签名 */
    if (config->hideversion == BF_FALSE) {
        bf_string_build(&host->host_signature, &len, "Buffalo/%s", VERSION);
    } else {
        bf_string_build(&host->host_signature, &len, "Buffalo");
    }
    bf_string_build(&host->header_host_signature.data,
                    &host->header_host_signature.len,
                    "Server: %s", host->host_signature);
    host->next = NULL;
    return host; 
}

void bf_config_set_init_values(void) {
    /* 初始化 values */
    config->timeout = 15;
    config->hideversion = BF_FALSE;
    config->keep_alive = BF_TRUE;
    config->keep_alive_timeout = 15;
    config->max_keep_alive_request = 50;
    config->resume = BF_TRUE;
    config->standard_port = 80;
    config->listen_addr = BF_DEFAULT_LISTEN_ADDR;
    config->serverport = 2001;
    config->symlink = BF_FALSE;
    config->nhosts = 0;
    config->user = NULL;
    config->open_flags = O_RDONLY | O_NONBLOCK;
    config->index_files = NULL;
    config->user_dir = NULL;

    /* 允许的最大请求 buffer size
     * 每个 chunk 4KB(4096 bytes)
     * 所以我们最大buffer size 是 32 KB
     */
    config->max_request_size = BF_REQUEST_CHUNK * 8;

    /* 插件 */
    config->plugins = bf_alloc(sizeof(struct bf_queue_s));

    /* 网络 */
    config->safe_event_write = BF_FALSE;

    /* 
     * 传输类型: 用于建立重定向 headers, values:
     *
     *   BF_TRANSPORT_HTTP
     *   BF_TRANSPORT_HTTPS
     *
     * 我们默认的是 'http'
     */
    config->transport = BF_TRANSPORT_HTTP

    /* 初始化 插件 列表 */
    bf_queue_init(config->plugins);
}

/* read main configuration from buffalo.conf */
void bf_config_start_configure(void) {
    unsigned long len;

    bf_config_set_init_values();
    bf_config_read_files(config->file_config, BF_DEFAULT_CONFIG_FILE);

    /* 载入 mimes */
    bf_mimetype_read_config();

    /* server 的基本信息 */
    if (config->hideversion == BF_FALSE) {
        bf_string_build(&config->server_software.data,
                        &len, "Buffalo/%s (%s)", VERSION, OS);
        config->server_software.len = len;
    } else {
        bf_string_build(&config->server_software.data, &len, "Buffalo Server");
        config->server_software.len = len;
    }
}

struct host *bf_config_host_find(bf_pointer host) {
    struct host_alias *entry;
    struct bf_queue_s *head;
    struct host *aux_host;

    aux_host = config->hosts;
    while (aux_host) {
        bf_queue_foreach(head, &aux_host->server_names) {
            entry = bf_queue_entry(head, struct host_alias, _head);
            if (entry->len == host.len && strncasecmp(entry->name, host.data, host.len) == 0) {
                return aux_host;
            }
        }
        aux_host = aux_host->next;
    }

    return NULL;
}

void bf_config_sanity_check() {
    /* 对当前用户检查 O_NOATIME
     * flags 在当前用户允许的情况下使用
     */
    int fd, flags = config->open_flags;

    flags |= O_NOTATIME;
    fd = open(config->file_config, flags);

    if (fd > -1) {
        config->open_flags = flags;
        close(fd);
    }
}