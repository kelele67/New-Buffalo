#ifndef BF_MEM_H
#define BF_MEM_H


/* 使用 typedef 命名数据类型 */
typedef struct {
    char *data;
    unsigned long len;
}bf_pointer;

/* short int list*/
/* 考虑换成由双向链表管理的内存池 */
struct list_sint {
    unsigned short int index;
    bf_pool_s value;
    struct list_sint *next;
};

typedef struct list_sint bf_list_sint_t;

#if ((__GNUC__ * 100 + __GNUC__MINOR__) > 430) /* gcc version > 4.3 */
#define ALLOCSZ_ATTR(x, ...) __attribute__ ((alloc_size(x, ##__VA_ARGS__)))
#else
#define ALLOCSZ_ATTR(x, ...)
#endif

void *bf_alloc(const size_t size);
void *bf_calloc(const size_t size);
void *bf_realloc(void *ptr, const size_t size);
void bf_free(void *ptr);
void bf_pointers_init(void);

/* bf_pointer_* */
bf_pointer bf_pointer_create(char *buf, long init, long end);
void bf_pointer_free(bf_pointer * p);
void bf_pointer_reset(bf_pointer * p);
void bf_pointer_print(bf_pointer p);
char *bf_pointer_to_buf(bf_pointer p);
void bf_pointer_set(bf_pointer * p, char *data);

#endif