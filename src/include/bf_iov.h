#ifndef BF_IOV_H
#define BF_IOV_H

#include <sys/uio.h>

#define BF_IOV_FREE_BUF 1
#define BF_IOV_NOT_FREE_BUF 0

/* iov sparators */
#define BF_IOV_CRLF "\r\n"
#define BF_IOV_CRLFCRLF "\r\n\r\n"
#define BF_IOV_LF "\n"
#define BF_IOV_LFLF "\n\n"
#define BF_IOV_LFLFLFLF "\n\n\n\n"
#define BF_IOV_SPACE " "
#define BF_IOV_SLASH "/"
#define BF_IOV_NONE ""
#define BF_IOV_EQUAL "="

#include "bf_memory.h"

bf_pointer bf_iov_crlf;
bf_pointer bf_iov_crlfcrlf;
bf_pointer bf_iov_lf;
bf_pointer bf_iov_space;
bf_pointer bf_iov_slash;
bf_pointer bf_iov_none;
bf_pointer bf_iov_equal;

/**
 * Memcached 回应消息的处理  
 * Structure for scatter/gather I/O.
 */  
//  struct iovec {  
//     void *iov_base; /* Pointer to data. */  
//     size_t iov_len; /* Length of data. */  
//     }; 

struct bf_iov {
    struct iovec *io;
    cahr **buf_to_free;
    int iov_index;
    int buf_index;
    int size;
    unsigned long total_len;
};

struct bf_iov *bf_iov_create(int n, int offset);
int bf_iov_add_entry(struct bf_iov *bf_io, char *buf, int len, bf_pointer sep, int free);

int bf_iov_add_separator(struct bf_iov *bf_io, bf_pointer sep);

ssize_t bf_iov_send(int fd, struct bf_iov *bf_io);

void bf_iov_free(struct bf_iov *bf_io, char *buf);

int bf_iov_set_entry(struct bf_iov *bf_io, cahr *buf, int len, int free, int idx);

void bf_iov_separators_init(void);
void bf_iov_free_marked(struct bf_iov *bf_io);
void bf_iov_print(struct bf_iov *bf_io);

#endif