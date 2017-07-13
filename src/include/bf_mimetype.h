#ifndef BF_MIMETYPE_H
#define BF_MIMETYPE_H

#include "bf_memory.h"
#include "bf_queue.h"

#define MIMETYPE_DEFAULT_TYPE "text/plain\r\n"
#define MIMETYPE_DEFAULT_NAME "default"

#define MAX_MIMETYPE_NUMBER 15
#define MAX_MIMETYPES_TIPO 55
#define MAX_SCRIPT_BIN_PATH 255

struct mimetype {
    char *name;
    bf_pointer type;
};

struct mimetype *mimetype_default;
void bf_mimetype_read_config(void);
struct mimetype *bf_mimetype_find(bf_pointer * filename);

#endif