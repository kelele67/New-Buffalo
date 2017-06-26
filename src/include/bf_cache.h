#ifndef BF_CACHE_H
#define BF_CACHE_H

#define BF_KNOWN_HEADERS 11 /* 服务器一共支持11种header */

/* 线程私有数据 TSD*/
/* iov header cache */
pthread_key_t bf_cache_iov_header;
/* request 的全部内容 Table of Content (toc) */
pthread_key_t bf_cache_header_toc;
/* 最后修改的 last modified*/
pthread_key_t bf_cache_header_lm;
/* 内容长度 content length */
pthread_key_t bf_cache_header_cl;
pthread_key_t bf_cache_utils_gmtime;

/* 建立一个cache_date结构来记录cache存在时间等信息*/
struct bf_cache_date_t {
    time_t unix_time;
    time_t expire;
    time_t last_access;
    bf_pointer date;
}

struct bf_cahce_date_t *bf_cache_file_date;

void bf_cache_thread_init(void);
void *bf_cache_get(pthread_key_t key);
char *bf_cache_file_date_get(time_t time);

#endfi