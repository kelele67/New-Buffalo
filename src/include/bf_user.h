#ifndef BF_USER_H
#define BF_USER_H

#include "bf_request.h"

/* User home string */
#define BF_USER_HOME '~'

gid_t egid;
uid_t euid;

/* user.c */
int bf_user_init(struct client_session *cs, struct session_request *sr);
int bf_user_set_uidgid(void);
int bf_user_undo_uidgid(void);

#endif