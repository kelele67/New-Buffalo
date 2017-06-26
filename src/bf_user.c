#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <grp.h>

#include "include/buffalo.h"
#include "include/bf_user.h"
#include "include/bf_http.h"
#include "include/bf_http_status.h"
#include "include/bf_memory.h"
#include "include/bf_string.h"
#include "include/bf_utils.h"
#include "include/bf_config.h"
#include "include/bf_debug.h"

int bf_user_init(struct client_session *cs, struct session_request *sr) {
    int limit;
    int offset = 2; /* user 前面还有 '/~'，所以偏移为2 */
    int user_len = 255;
    char user[user_len], *user_uri;
    struct passwd *s_user;

    if (sr->uri_processed.len <= 2) {
        return -1;
    }

    limit = bf_string_char_search(sr->uri_processed.data + offset, '/',
                                    sr->uri_processed.len);
    
    if (limit == -1) {
        limit = (sr->uri_processed.len) - offset;
    }

    if (limit + offset >= (user_len)) {
        return -1;
    }

    strncpy(user, sr->uri_processed.data + offset, limit);
    user[limit] = '\0';

    BF_TRACE("user: '%s'", user);

    /* 检查系统 user */
    if ((s_user = getpwnam(user)) == NULL) {
        /* getpwnam:获取用户登录相关信息 */
        bf_request_error(BF_CLIENT_NOT_FOUND, cd, sr);
        return -1;
    }

    if (sr->uri_processed.len > (offset + limit)) {
        user_uri = bf_alloc(sr->uri_processed.len);
        if (!user_uri) {
            return -1;
        }

        strncpy(user_uri,
                sr->uri_processed.data + (offset + limit),
                sr->uri_processed.len - offset - limit);
        user_uri[sr->uri_processed.len - offset - limit] = '\0';

        bf_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s%s", s_user->pw_dir, ocnfig->user_dir, user_uri);
        bf_free(user_uri);
    } else {
        bf_string_build(&sr->real_path.data, &sr->real_path.len,
                        "%s/%s", s_user->pw_dir, config->user_dir);
    }

    sr->user_home = BF_TRACE;
    return 0;
}

/* 改变 process user userid, user 的 groupid */
int bf_user_set_uidgid() {
    struct passwd *usr;

    /* 取得执行目前进程有效用户识别码uid */
    EUID = (gid_t) geteuid();
    /* 取得执行目前进程有效组识别码gid */
    EGID = (gid_t) getegid();

    /* 是否以 root 身份登录 */
    if (geteuid() == 0 && config->user) {
        /*struct rlimit {
　　     *rlim_t rlim_cur;
　　     *rlim_t rlim_max;
        };
        */
        struct rlimit rl;

        /* 如果是超级用户 */
        rl.rlim_cur = rl.rlim_max;
        /* 判断设定的资源使用限制 是否超过 RLIMIT_NOFILE(比进程可打开的最大文件描述词大一的值) 是否成功*/
        /* 成功返回0， 不成功返回-1 */
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            bf_warn("setrlimit(RLIMIT_NOFILE) failed");
        }

        /* 检查用户是否存在 */
        if ((user = getpwnam(config->user)) == NULL) {
            bf_err("Invalid user '%s'", config->user);
        }

        if (initgroups(config->user, usr->pw_gid) != 0) {
            bf_err("initgroups() failed");
        }

        /* 改变进程 UID GID */
        if (setuid(usr->pw_uid) == -1) {
            bf_err("I can't change the UID to %u", usr->pw_uid);
        }
        if (setgid(usr->pw_gid) == -1) {
            bf_err("I can't change the GID to %u", usr->pw_gid);
        } 

        EUID = geteuid();
        EGID = getegid();
    }
    return 0;
}

/* 把进程返回到最初的user */
int bf_user_undo_uidgid() {
    if (EUID == 0) {
        seteuid(EUID);
        setegid(EGID);
    }
    return 0;
}