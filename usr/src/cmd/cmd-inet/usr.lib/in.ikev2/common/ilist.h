/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _ILIST_H
#define	_ILIST_H

/* A very thin wrapper around list_t to include the size of the list */

#include <inttypes.h>
#include <sys/list.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ilist {
	list_t	ilist_list;
	size_t	ilist_size;
} ilist_t;

/* Use inline functions instead of macros for better type checking */
inline void
ilist_create(ilist_t *list, size_t size, size_t offset)
{
	list_create(&list->ilist_list, size, offset);
	list->ilist_size = 0;
}

inline void
ilist_destroy(ilist_t *list)
{
	list_destroy(&list->ilist_list);
}

inline void
ilist_insert_after(ilist_t *list, void *object, void *nobject)
{
	list_insert_after(&list->ilist_list, object, nobject);
	list->ilist_size++;
}

inline void
ilist_insert_before(ilist_t *list, void *object, void *nobject)
{
	list_insert_before(&list->ilist_list, object, nobject);
	list->ilist_size++;
}

inline void
ilist_insert_head(ilist_t *list, void *object)
{
	list_insert_head(&list->ilist_list, object);
	list->ilist_size++;
}

inline void
ilist_insert_tail(ilist_t *list, void *object)
{
	list_insert_tail(&list->ilist_list, object);
	list->ilist_size++;
}

inline void
ilist_remove(ilist_t *list, void *object)
{
	list_remove(&list->ilist_list, object);
	list->ilist_size--;
}

inline void *
ilist_remove_head(ilist_t *list)
{
	void *obj = list_remove_head(&list->ilist_list);
	if (obj != NULL) {
		VERIFY3U(list->ilist_size, >, 0);
		list->ilist_size--;
	}
	return (obj);
}

inline void *
ilist_remove_tail(ilist_t *list)
{
	void *obj = list_remove_tail(&list->ilist_list);
	if (obj != NULL) {
		VERIFY3U(list->ilist_size, >, 0);
		list->ilist_size--;
	}
	return (obj);
}

inline void *
ilist_head(ilist_t *list)
{
	return (list_head(&list->ilist_list));
}

inline void *
ilist_tail(ilist_t *list)
{
	return (list_tail(&list->ilist_list));
}

inline void *
ilist_next(ilist_t *list, void *object)
{
	return (list_next(&list->ilist_list, object));
}

inline void *
ilist_prev(ilist_t *list, void *object)
{
	return (list_prev(&list->ilist_list, object));
}

inline void
ilist_move_tail(ilist_t *dst, ilist_t *src)
{
	list_move_tail(&dst->ilist_list, &src->ilist_list);
}

inline int
ilist_is_empty(ilist_t *list)
{
	int ret = list_is_empty(&list->ilist_list);
	if (ret == 0)
		VERIFY3S(list->ilist_size, >, 0);
	else
		VERIFY3S(list->ilist_size, ==, 0);

	return (ret);
}

inline size_t
ilist_size(ilist_t *list)
{
	return (list->ilist_size);
}

#ifdef __cplusplus
}
#endif

#endif /* _ILIST_H */
