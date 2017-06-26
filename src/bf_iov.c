#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <errno.h>
#include <limits.h>

#include "include/buffalo.h"
#include "include/bf_header.h"
#include "include/bf_memory.h"
#include "include/bf_utils.h"
#include "include/bf_iov.h"

struct bf_iov *bf_iov_create(int n, int offset) {
    struct bf_iov *iov;

    iov = bf_alloc(sizeof(struct bf_Iov));
    iov->iov_index = offset;
    iov->io = bf_alloc(n * sizeof(struct iovec));
    iov->buf_to_free = bf_alloc(n * sizeof(char *));
    iov->buf_index = 0;
    iov->total_len = 0;
    iov->size = n;

    return iov;
}

int bf_iov_add_entry(struct bf_iov *bf_io, char *buf, int len, bf_pointer sep, int free) {
    if (buf) {
        bf_io->io[bf_io->iov_index].iov_base = (unsigned char *) buf;
        bf_io->io[bf_io->iov_index].iov_len = len;
        bf_io->iov_index++;
        bf_io->total_len += len;
    }

#ifdef DEBUF_IOV
    if (bf_io->iov_index > bf_io->size) {
        printf("\nDEBUG IOV :: ERROR, Broken array size in");
        printf("\n          '''%s'''", buf);
        /* 清空文件缓冲区 */
        fflush(stdout);
    }
#endif

    /* 添加 separator */
    if (sep.len > 0) {
        bf_io->io[bf_io->iov_index].iov_base = sep.data;
        bf_io->io[bf_io->iov_index].iov_len = sep.len;
        bf_io->iov_index++;
        bf_io->total_len += sep.len;
    }

    return bf_io->iov_index;
}

int bf_iov_set_entry(struct bf_iov *bf_io, char *buf, int len, int free, int index) {
    bf_io->io[index].iov_base = buf;
    bf_io->io[index].iov_len = len;
    bf_io->total_len += len;

    if (free == BF_IOV_FREE_BUF) {
        _bf_iov_set_free(bf_io, buf);
    }
    return 0;
}

void _bf_iov_set_free(struct bf_iov *bf_io, char *buf) {
    bf_io->buf_to_free[bf_io->buf_index] = (char *) buf;
    bf_io->buf_index++;
}

ssize_t bf_iov_send(int fd, struct bf_iov *bf_io) {
    ssize_t n = -1;

    n = writev(fd, bf_io->io, bf_io->iov_index);
    if (n < 0) {
        BF_TRACE(" writev() error on FD %i", fd);
        perror("writev");
    }

    return n;
}

void bf_iov_free(struct bf_iov *bf_io) {
    bf_iov_free_marked(bf_io);
    bf_free(bf_io->buf_to_free);
    bf_free(bf_io->io);
    bf_free(bf_io);
}

void bf_iov_free_marked(struct bf_iov *bf_io) {
    int i, limit = 0;

    limit = bf_io->buf_index;

    for (i = 0; i < limit; i++) {

#ifdef DEBUG_IOV
        printf("\nDEBUG IOV :: going free (index: %i/%i): %s", i, limit, bf_io->buf_to_free[i]);
        fflush(stdout);
#endif
        bf_free(bf_io->buf_to_free[i]);
    }

    bf_io->iov_index = 0;
    bf_io->buf_index = 0;
}

void bf_iov_print(struct bf_iov *bf_io) {
    int i, j;
    char *c;
    
    for (i = 0; i < bf_io->iov_index; i++) {
        printf("\n[index=%i len=%i]\n'", i, (int) bf_io->io[i].iov_len);
        fflush(stdout);
        for (j = 0; j < bf_io->io[i].iov_len; j++) {
            c = bf_io->io[i].iov_base;
            printf("%c", c[j]);
            fflush(stdout);
        }
        printf("'[end=%i]\n", j);
        fflush(stdout);
    }
}

void bf_iov_separators_init() {
    bf_pointer_set(&bf_iov_crlf, BF_IOV_CRLF);
    bf_pointer_set(&bf_iov_lf, BF_IOV_LF);
    bf_pointer_set(&bf_iov_space, BF_IOV_SPACE);
    bf_pointer_set(&bf_iov_slash, BF_IOV_SLASH);
    bf_pointer_set(&bf_iov_none, BF_IOV_NONE);
    bf_pointer_set(&bf_iov_equal, BF_IOV_EQUAL);
}