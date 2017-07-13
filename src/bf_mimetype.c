#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "bf_mimetype.h"
#include "bf_memory.h"
#include "bf_string.h"
#include "bf_utils.h"
#include "bf_config.h"
#include "bf_request.h"
#include "buffalo.h"
#include "bf_queue.h"
#include "bf_debug.h"


/* 最常使用的 mime types 数量 */
#define MIME_COMMON 10

static struct mimetype *mimecommon = NULL; /* old top used mime types */
static struct mimetype *mimearr = NULL; /* old the rest of the mime types */
static int nitem = 0; /* amount of available mime types */

/* add an item to the mimecommon or mimearr variables */
#define add_mime(item, m) ({ \
    m = (nitem == 0) ? bf_alloc(sizeof(struct mimetype)) : \
        bf_realloc(m, (nitem + 1) * (sizeof(struct mimetype))); \
        m[nitem++] = item; \
})

static int mime_cmp(const void *m1, const void *m2) {
    struct mimetype *mi1 = (struct mimetype *) m1;
    struct mimetype *mi2 = (struct mimetype *) m2;

    return strcmp(mi1->name, mi2->name);
}

/* 在请求资源中寻找匹配 mime type */
static inline struct mimetype *bf_mimetype_lookup(char *name) {
    int i;
    struct mimetype tmp;

    /*
     * 用简单的启发式搜索去猜测收到的是什么 mime type,
     * 我们一般收到的是  html/css/ 或者 images
     *
     * 首先在用的最多的10个 mimecommon 里面直接搜索,
     * 如果没有的话 我们再进行二分搜索
     */
    for (i = 0; i < MIME_COMMON; i++) {
        if (!(strcasecmp(name, mimecommon[i].name)) {
            return &mimecommon[i];
        }
    }

    tmp.name = name;
    return bsearch(&tmp, mimearr, nitem, sizeof(struct mimetype), mime_cmp);
}

static int bf_mimetype_add(char *name, char *type, int common) {
    int len = strlen(type) + 3;
    struct mimetype new_mime;

    new_mime.name = name;

    new_mime.type.data = bf_alloc(len);
    new_mime.type.len = len - 1;
    strcpy(new_mime.type.data, type);
    strcat(new_mime.type.data, BF_CRLF);
    new_mime.type.data[len - 1] = '\0';

    /* 把新加入的 mime 加入到数组最后 */
    common ? add_mime(new_mime, mimecommon) : add_mime(new_mime, mimearr);

    bf_free(type);
    return 0;
}

/* 将两个 mime 数组 导入 缓存中 */
void bf_mimetype_read_config() {
    char path[MAX_PATH];
    int i = 0;
    struct bf_config *cnf;
    struct bf_config_section *section;
    struct bf_config_entry *entry;

    /* Read mime types configuration file */
    snprintf(path, MAX_PATH, "%s/buffalo.mime", config->serverconf);
    cnf = bf_config_create(path);

    /* 获取 mimetypes 标签 */
    section = bf_config_section_get(cnf, "MIMETYPES");
    if (!section) {
        bf_err("Error: Invalid mime type file");
    }

    entry = section->entry;
    while (entry) {
        if (i < MIME_COMMON) {
            if (bf_mimetype_add(entry->key, entry->val, 1) != 0) {
                bf_err("Error: Loading mime types");
            }
        } else {
            if (i == MIME_COMMON) {
                nitem = 0; /* 重置计数 */
            }
            if (bf_mimetype_add(entry->key, entry->val, 0) != 0) {
                bf_err("Error: Loading mime types");
            }
        }
        entry = entry->next;
        i++;
    }

    /* 以升序快排二分搜索结果 */
    qsort(mimearr, nitem, sizeof(struct mimetype), mime_cmp);

    /* 建立 默认 mime type */
    mimetype_default = bf_calloc(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_NAME;
    bf_pointer_set(&mimetype_default->type, MIMETYPE_DEFAULT_TYPE);
}

struct mimetype *bf_mimetype_find(bf_pointer * filename) {
    int j, len;

    j = len = filename->len;

    /* 寻找扩展名 */
    while (filename->data[j] != '.' && j >= 0) {
        j--;
    }

    if (j == 0) {
        return NULL;
    }
    
    /* 在请求资源中寻找匹配 mime type */
    return bf_mimetype_lookup(filename->data + j + 1);
}
