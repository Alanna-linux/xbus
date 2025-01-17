#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "vref.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

/** Visibility attribute */
#if defined(__GNUC__) && __GNUC__ >= 4
#define XBUS_EXPORT __attribute__ ((visibility("default")))
#else
#define XBUS_EXPORT
#endif

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

#define container_of(ptr, sample, member) ({\
	(__typeof__(sample)) ((char *)(ptr) -  \
			offsetof(__typeof__(*sample), member));})

/**
 * list_entry - get the containing structure for the member.
 * @ptr:	the pointer to the member.
 * @type:	the type of the containing struct.
 * @member:	the name of the member in the containing struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

#define list_last_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_last_entry(ptr, type, member) : NULL)

#define list_for_each_safe(pos, tmp, head, member) \
	for (pos = container_of((head)->next, pos, member), \
		tmp = container_of((pos)->member.next, tmp, member); \
		&pos->member != (head); \
		pos = tmp, \
		tmp = container_of(pos->member.next, tmp, member))

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, pos, member);		\
		&pos->member != (head);					\
		pos = list_entry(pos->member.next, pos, member))

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, pos, member)

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_struct within the struct.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_for_each_prev_safe(pos, tmp, head, member) \
	for (pos = container_of((head)->prev, pos, member), \
		tmp = container_of((pos)->member.prev, tmp, member); \
		&pos->member != (head); \
		pos = tmp, \
		tmp = container_of(pos->member.prev, tmp, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, pos, member); 		\
		&pos->member != (head); 				\
		pos = list_entry(pos->member.prev, pos, member))

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void __list_add(struct list_head *_new,
				struct list_head *prev,
				struct list_head *next)
{
	prev->next = _new;
	_new->prev = prev;
	_new->next = next;
	next->prev = _new;
}

static inline void list_add(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head, head->next);
}

static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *list)
{
	__list_del(list->prev, list->next);
	list->next = list;
	list->prev = list;
}

#endif
