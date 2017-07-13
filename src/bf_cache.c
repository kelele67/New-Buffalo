#include <pthread.h>
#include "bf_iov.h"
#include "bf_cache.h"
#include "bf_request.h"

#include <stdio.h>
#include <stdlib.h>
#include "bf_utils.h"

/* 每当有新线程建立的时候都调用这个函数 */
void bf_cache_thread_init() {
    bf_pointer *cache_header_lm;
    bf_pointer *cache_header_cl;
    struct tm *cache_utils_gmtime;
    struct bf_iov *cache_iov_header;

    /* cache header request 的 last modified */
    cache_header_lm = bf_calloc(sizeof(bf_pointer));
    cache_header_lm->data = bf_calloc(32);
    cache_header_lm->len = -1;
    /* 把 cache_header_lm 存储在线程中 */
    pthread_setspecific(bf_cache_header_lm, cahce_header_lm);

    /* cache header request 的 content length */
    cache_header_cl = bf_calloc(sizeof(bf_pointer));
    cache_header_cl->data = bf_calloc(BF_UTILS_INT2BFP_BUFFER_LEN);
    cache_header_cl->len = -1;
    pthread_setspecific(bf_cache_header_cl, (void *) cache_header_cl);

    /* cache iov header struct */
    cache_iov_header = bf_iov_create(32, 0);
    pthread_setspecific(bf_cache_iov_header, (void *) cache_iov_header);

    /* cache gmtime buffer */
    cache_utils_gmtime = bf_alloc(sizeof(struct tm));
    pthread_setspecific(bf_cache_utils_gmtime, (void *) cache_utils_gmtime);
}

void *bf_cache_get(pthread_key_t key) {
    return (void *) pthread_getspecific(key);
}