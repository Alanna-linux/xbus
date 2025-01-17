/**
 *   Copyright (C) 2019 All rights reserved.
 *
 *   FileName      ：wrapper.h
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2020-08-08
 *   Description   ：
 */

#ifndef _WRAPPER_H
#define _WRAPPER_H

#include <stdio.h>
#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_MEMORY_DEBUG

static __used int __mem_id = -1;
void *xmalloc_dbg(const char *tag, int *id, size_t size);
void *xzmalloc_dbg(const char *tag, int *id, size_t size);
void *xrealloc_dbg(const char *tag, int *id, void *p, size_t size);
void xfree_dbg(const char *tag, int *id, void *p);
void *xstrdup_dbg(const char *tag, int *id, const char *str);
#define xmalloc(size) \
	xmalloc_dbg(THIS_MODULE, &__mem_id, size)

#define xzmalloc(size) \
	xzmalloc_dbg(THIS_MODULE, &__mem_id, size)

#define xrealloc(p, size) \
	xrealloc_dbg(THIS_MODULE, &__mem_id, p, size)

#define xfree(p) \
	xfree_dbg(THIS_MODULE, &__mem_id, p)

#define xstrdup(s) \
	xstrdup_dbg(THIS_MODULE, &__mem_id, s)

#else

void *xmalloc_common(size_t size);
void *xrealloc_common(void *p, size_t size);
void xfree_common(void *ptr);
void *xstrdup_common(const char *str);
#define xmalloc(size)		xmalloc_common(size)
#define xzmalloc(size)		xzmalloc_common(size)
#define xrealloc(p, size) 	xrealloc_common(p, size)
#define xfree(p)		xfree_common(p)
#define xstrdup(s)              xstrdup_common(s)

#endif

int mem_init(void);
void mem_close(void);
void mem_register_service(const char *prefix, int id);
char *strdup2(const char *str);

#ifdef __cplusplus
}
#endif

#endif
