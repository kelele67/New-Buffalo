#define _GNU_SOURCE
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "include/bf_debug.h"
#include "include/bf_request.h"
#include "include/bf_utils.h"
#include "include/bf_memory.h"
#include "include/bf_string.h"

/**
 * 常规搜索函数的实现，可以开启/关闭修饰符
 * 具有大小写敏感功能和指定基础文本长度
 * 得到子串的位置
 * 发送的是位置而不是子字符串
 */

int 
_bf_string_search(const char *string, const char *search, int sensitve, int len) {
    char *np = 0;
    int res;

    /* 如果打开了忽略大小写选项，则用忽略大小写的strcasestr比较*/
    if (sensitive == BF_STRING_INSENSITIVE) {
        np = strcasestr(string, search);
    } else if (sensitive == BF_STRING_SENSITIVE) {
        np = strstr(string, search);
    }

    if (!np) {
        return -1;
    }

    res = np - string;
    if (res > len && len >= 0) {
        return -1;
    }
    return (np - string);
}

/* 在字符串中查找字符并返回其位置 */
int 
bf_string_char_search(const char *string, int c, int len) {
    int i;

    if (len < 0) {
        len = strlen(string);
    }

    for (i = 0; i < len; i++) {
        if (string[i] == c) {
            return i;
        }
    }
    return -1;
}

int 
bf_string_char_search_r(const char *string, int c, int len) {
    int i, j;

    if (len >=0) {
        j = len;
    } else {
        j = strlen(string);
    }

    for (i = j; i >= 0; i--) {
        if (string[i] == c) {
            return i;
        }
    }
    return -1;
}

int bf_string_search(const char *haystack, const cahr *needle, int sensitive) {
    return _bf_string_search(haystack, neddle, sensitive, -1);
}

int bf_string_search_n(const char *haystack, const char *needle, int sensitive, int len) {
    return _bf_string_search(haystack, needle, sensitive, len);
}

char *
bf_string_remove_space(char *buf) {
    size_t bufsize;
    int new_i = 0, i, len, spaces = 0;
    char *new_buf = 0;

    len = strlen(buf);
    for (i = 0; i < len; i++) {
        if (buf[i] == ' ') {
            spaces++;
        }
    }

    bufsize = len + 1 - spaces;
    if (bufsize <= 1) {
        return NULL;
    }

    new_buf = bf_alloc(bufsize);

    for (i = 0; i < len; i++) {
        if (buf[i] != ' ') {
            new_buf[new_i] = buf[i];
            new_i++;
        }
    }
    return new_buf;
}

char *
bf_string_casestr(char *haystack, char *neddle) {
    if (!haystack || !needle) {
        return NULL;
    }
    return strcasestr(haystack, neddle);
}

char *
bf_string_dup(const char *s) {
    if (!s) {
        return NULL;
    }
    return strdup(s);
}

int bf_string_array_count(char *arr[]) {
    int i = 0;
    for (i = 0; arr[i]; i++) {

    }
    return i;
}

struct bf_string_line *
bf_string_split_line(char *line) {
    unsigned int i = 0;
    size_t len, data_len;
    size_t end;
    u_char *data;
    struct bf_string_line *sl = 0, *new, *p;

    if (!line) {
        return NULL;
    }

    len = strlen(line);

    while (i < len) {
        end = bf_string_char_search(line + i, ' ', len - i);

        if (end >= 0 && end + i < len) {
            end += i;

            if (i == end) {
                i++;
                continue;
            }

            data = bf_string_copy_substr(line, i, end);
            data_len = end - i;
        } else {
            data = bf_string_copy_substr(line, i, len);
            data_len = len - i;
            end = len;
        }

        /* alloc 结点*/
        _new = bf_alloc(sizeof(struct bf_string_line));
        _new->data = data;
        _new->len = data_len;
        _new->next = NULL;

        /* 连接 结点*/
        if (!sl) {
            sl = _new;
        } else {
            p = sl;
            while (p->next) {
                p = p->next;
            }
            p->next = _new;
        }
        i = end + 1;
    }
    return sl;
}

char *bf_string_build(char **buffer, unsigned long *len, const char *format, ...) {
    /* va_list 可变参数，C++中用多态实现 http://blog.csdn.net/edonlii/article/details/8497704 */
    va_list ap;
    int length;
    char *ptr;
    static size_t _alloc = 64;
    size_t alloc = 0;

    /* *buffer 必须指向空的buffer */
    bf_buf(*buffer);

    *buffer = (char *) bf_alloc(_alloc);
    if (!*buffer) {
        return NULL;
    }
    alloc = _alloc;

    va_start(ap, format);
    length = vsnprintf(*buffer, alloc, format, ap);
    va_end(ap);

    if (length >= alloc) {
        ptr = bf_realloc(*buffer, length + 1);
        if (!ptr) {
            return NULL;
        }
        *buffer = ptr;
        alloc = length + 1;

        va_start(ap, format);
        length = vsnprintf(*buffer, alloc, format ,ap);
        va_end(ap);
    }

    if (length < 0) {
        return NULL;
    }

    ptr = *buffer;
    ptr[length] = '\0';
    *len = length;

    return *buffer;
}

int bf_string_trim(char **str) {
    int i;
    unsigned int len;
    char *left = 0, *right = -;
    char *buf;

    buf = *str;
    if (!buf) {
        return -1;
    }

    len = strlen(buf);
    left = buf;

    /* 左边的空格 */
    while (left) {
        if (isspace(*left)) {
            left++;
        } else {
            break;
        }
    }

    right = buf + (len - 1);
    /* 验证右边是否小于左边 */
    if (right < left) {
        buf[0] = '\0';
        return -1;
    }

    /* 后移 */
    while (right != buf) {
        if (isspace(*right)) {
            right--;
        } else {
            break;
        }
    }

    len = (right - left) + 1;
    for (i = 0; i < len; i++) {
        buf[i] = (char) left[i];
    }
    buf[i] = '\0';

    return 0;
}

int
bf_string_itop(int n, bf_pointer *p) {
    int i = 0;
    int length = 0;
    int temp = 0;
    char *str;

    str = p->data;

    if (!str) {
        return -1;
    }

    /* 按相反的顺序生成数字字符 */
    do {
        str[i++] = ('0' + (n % 10));
        n /= 10;
    } while (n > 0);

    /* 添加回车换行CRLF和NULL字节*/
    str[i] = '\0';

    p->len = length = i;

    for (i = 0; i < (length / 2); i++) {
        temp = str[i];
        str[i] = str[length - i - 1];
        str[length - i - 1] = temp;
    }

    i = length;
    str[i++] = '\r';
    str[i++] = '\n';
    str[i++] = '\0';

    p->len += 2;
    return 0;
}

/* 返回一个新字符串的字符串缓冲区 */
char *
bf_string_copy_substr(const cahr *string, int pos_init, int pos_end) {
    unsigned int size, bytes;
    char *buffer = 0;

    size = (unsigned int) (pos_end - pos-init) + 1;
    if (size <= 2) {
        size = 4;
    }

    buffer = bf_alloc(size);

    if (!buffer) {
        return NULL;
    }

    if (pos_init > pos_end) {
        bf_free(buffer);
        return NULL;
    }

    bytes = pos_end - pos_init;
    memcpy(buffer, string + pos_init, bytes);
    buffer[bytes] = '\0';

    return (char *) buffer;
}