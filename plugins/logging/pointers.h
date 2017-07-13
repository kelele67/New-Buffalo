#incldue "bf_memory.h"

/* Request error messages for log file */
#define ERROR_MSG_400 "[error 400] Bad Request"
#define ERROR_MSG_403 "[error 403] Forbidden"
#define ERROR_MSG_404 "[error 404] Not Found"
#define ERROR_MSG_405 "[error 405] Method Not Allowed"
#define ERROR_MSG_408 "[error 408] Request Timeout"
#define ERROR_MSG_411 "[error 411] Length Required"
#define ERROR_MSG_413 "[error 413] Request Entity Too Large"
#define ERROR_MSG_500 "[error 500] Internal Server Error"
#define ERROR_MSG_501 "[error 501] Not Implemented"
#define ERROR_MSG_505 "[error 505] HTTP Version Not Supported"

#define BF_LOGGING_IOV_DASH " - "
#define BF_LOGGING_IOV_SPACE " "
#define BF_LOGGING_IOV_EMPTY "-"

/* bf pointers for errors */
bf_pointer error_msg_400;
bf_pointer error_msg_403;
bf_pointer error_msg_404;
bf_pointer error_msg_405;
bf_pointer error_msg_408;
bf_pointer error_msg_411;
bf_pointer error_msg_413;
bf_pointer error_msg_500;
bf_pointer error_msg_501;
bf_pointer error_msg_505;

/* bf pointer for IOV */
bf_pointer bf_logging_iov_dash;
bf_pointer bf_logging_iov_space;
bf_pointer bf_logging_iov_lf;
bf_pointer bf_logging_iov_empty;

/* functions */
void bf_logging_init_pointers();
