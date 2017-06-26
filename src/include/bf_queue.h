#ifndef BF_QUEUE_H
#define BF_QUEUE_H

#include <stddef.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/**
 *container_of宏根据一个结构体变量中的一个域成员变量的指针来获取指向整个结构体变量的指针
 *典型的应用就是如下根据链表节点获取链表上的元素对象
 */
 #define container_of(ptr, type, member) ({              \
     const typeof( ((tyoe *)0)->member) *__mptr = (ptr); \
     (type *)( (char *)__mptr - offsetof(type, member) ); \
 })
 
typedef struct bf_queue_s  bf_queue_t;

struct bf_queue_s {
    bf_queue_s  *prev;
    bf_queue_s  *next;
};

/* 考虑用宏定义的话会更简洁 */
static inline void bf_queue_init(bf_queue_s *queue) {
    queue->next = queue;
    queue->prev = queue;
}

static inline void __bf_queue_add(bf_queue_s *_new, bf_queue_s *prev, bf_queue_s *next) {
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void bf_queue_add(bf_queue_s *_new, bf_queue_s *head) {
    __bf_queue_add(_new, head->prev, head);
}

static inline void __bf_queue_del(bf_queue_s *prev, bf_queue_s *next) {
    prev->next = next;
    next->prev = prev;
}

static inline void bf_queue_del(bf_queue_s *entry) {
    __bf_queue_del(entry->prev, entry->next);
    entry->prev = NULL;
    entry->next = NULL;
}

static inline int bf_queue_is_empty(bf_queue_s *head) {
    if (head->next == head) {
        return 0;
    } else {
        return -1;
    }
}

#define bf_queue_foreach(curr, head) for (curr = (head)->next; curr != (head); curr = curr->next)
#define bf_queue_foreach_safe(curr, n, head) \
    for (curr = (head)->next, n = curr->nextl curr != (head); curr = n, n = curr->next)

#define bf_queue_entry(ptr, type, member) container_of(ptr, type, member)

/* 双向链表的第一个结点 */
#define bf_queue_entry_first(ptr, type, member) container_of(ptr->next, type, member)

/* 最后一个结点 */
#define bf_queue_entry_last(ptr, type, member) container_of(ptr->prev, type, member)

/* 下一个结点 */
#define bf_queue_entry_next(ptr, type, member, head) \
    container_of(ptr->next, type, member); \
    if (ptr->next == (head)->prev) ptr = head; else ptr = ptr->next;

#endif
