/**
 *   Copyright (C) 2020 All rights reserved.
 *
 *   FileName      : compiler.h
 *   Author        : zhujiongfu
 *   Email         : zhujiongfu@live.cn
 *   Date          : 2020-08-26
 *   Description   :
 */
#ifndef _HAL_COMPILER_H
#define _HAL_COMPILER_H

#ifdef __GNUC__
#include "compiler-gcc.h"
#endif

#include <stdint.h>

#ifndef __always_inline
#define __always_inline inline
#endif

#define __READ_ONCE_SIZE						\
({									\
	switch (size) {							\
	case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;	\
	case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;	\
	case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;	\
	case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;	\
	default:							\
		barrier();						\
		__builtin_memcpy((void *)res, (const void *)p, size);	\
		barrier();						\
	}								\
})

#ifdef CONFIG_KASAN
/*
 * This function is not 'inline' because __no_sanitize_address confilcts
 * with inlining. Attempt to inline it may cause a build failure.
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
 * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
 */
static __no_sanitize_address __maybe_unused
void __read_once_size_nocheck(const volatile void *p, void *res, int size)
{
        __READ_ONCE_SIZE;
}
#else
static __always_inline
void __read_once_size_nocheck(const volatile void *p, void *res, int size)
{
        __READ_ONCE_SIZE;
}
#endif

static __always_inline
void __read_once_size(const volatile void *p, void *res, int size)
{
	__READ_ONCE_SIZE;
}

#define __READ_ONCE(x, check)                                           \
({                                                                      \
        union { typeof(x) __val; char __c[1]; } __u;                    \
	if (check)                                                      \
		__read_once_size(&(x), __u.__c, sizeof(x));             \
	else                                                            \
		__read_once_size_nocheck(&(x), __u.__c, sizeof(x));     \
	__u.__val;                                                      \
})
#define READ_ONCE(x) __READ_ONCE(x, 1)

/*
 *  * Use READ_ONCE_NOCHECK() instead of READ_ONCE() if you need
 *   * to hide memory access from KASAN.
 *    */
#define READ_ONCE_NOCHECK(x) __READ_ONCE(x, 0)

static __always_inline
void __write_once_size(volatile void *p, void *res, int size)
{
        switch (size) {
	case 1: *(volatile uint8_t *)p = *(uint8_t *)res; break;
	case 2: *(volatile uint16_t *)p = *(uint16_t *)res; break;
	case 4: *(volatile uint32_t *)p = *(uint32_t *)res; break;
	case 8: *(volatile uint64_t*)p = *(uint64_t *)res; break;
	default:
		barrier();
		__builtin_memcpy((void*)p,(const void*)res, size);
		barrier();
	}
}

#define WRITE_ONCE(x, val)						\
({									\
	union { typeof(x) __val; char __c[1]; } __u =			\
		{ .__val = (__force typeof(x)) (val) };			\
	__write_once_size(&(x), __u.__c, sizeof(x));			\
	__u.__val;							\
})

#endif
