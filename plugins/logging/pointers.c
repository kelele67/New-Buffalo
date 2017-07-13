#include "logging.h"
#include "bf_plugin.h"
#include "pointers.h"

void bf_logging_init_pointers() {
    /* Writter helpers */
    bf_api->pointer_set(&bf_logging_iov_dash, MK_LOGGING_IOV_DASH);
    bf_api->pointer_set(&bf_logging_iov_space, MK_IOV_SPACE);
    bf_api->pointer_set(&bf_logging_iov_lf, MK_IOV_LF);
    bf_api->pointer_set(&bf_logging_iov_empty, MK_LOGGING_IOV_EMPTY);

    /* Error messages */
    bf_api->pointer_set(&error_msg_400, ERROR_MSG_400);
    bf_api->pointer_set(&error_msg_403, ERROR_MSG_403);
    bf_api->pointer_set(&error_msg_404, ERROR_MSG_404);
    bf_api->pointer_set(&error_msg_405, ERROR_MSG_405);
    bf_api->pointer_set(&error_msg_408, ERROR_MSG_408);
    bf_api->pointer_set(&error_msg_411, ERROR_MSG_411);
    bf_api->pointer_set(&error_msg_413, ERROR_MSG_413);
    bf_api->pointer_set(&error_msg_500, ERROR_MSG_500);
    bf_api->pointer_set(&error_msg_501, ERROR_MSG_501);
    bf_api->pointer_set(&error_msg_505, ERROR_MSG_505);
}