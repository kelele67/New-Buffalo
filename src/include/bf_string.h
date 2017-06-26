#ifndef BF_STRING_H
#define BF_STRING_H

#include "bf_memory.h"

/* 关闭忽略大小写敏感sensitive选项 */
/* 即大小写敏感 */
#define BF_STRING_SENSITIVE 0

/* 打开忽略大小写敏感sensitive选项 */
#define BF_STRING_INSENSITIVE 1

struct bf_string_line {
    u_char *data;
    size_t len;
    struct bf_string_line *next;
}

/* 在字符串中查找字符并返回其位置 */
int bf_string_char_search(const char *string, int c, int len);

/* 在reverse的字符串中查找字符并返回其位置 */
int bf_string_char_search_r(const char *string, int c, int len);

/* 找到并且返回子串的位置 */
int bf_string_search(const cahr *haystack, const char *neddle, int sensitive);

/* 找到子串，比较前n个字符*/
int bf_string_search_n(const cahr *haystack, const char *neddle, int sensitive, int len);

char *bf_string_remove_space(char *buf);
char *bf_string_casestr(char *haystack, cahr *needle);
char *bf_string_dup(const char *s);
int bf_string_array_count(char *arr[]);
struct bf_string_line *bf_string_split_line(char *line);
int bf_string_trim(char **str);
char *bf_string_build(char **buffer, unsigned long *len, const char *format, ...);
int bf_string_itop(int n, bf_pointer *p);
char *bf_string_copy_substr(const char *string, int pos_init, int pos_end);

#endif
