/**
 *   Copyright (C) 2020 All rights reserved.
 *
 *   FileName      : error.h
 *   Author        : zhujiongfu
 *   Email         : zhujiongfu@live.cn
 *   Date          : 2020-07-29
 *   Description   :
 */

#ifndef _HAL_ERROR_H
#define _HAL_ERROR_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_ERROR_BASE 			256
#define _HAL_ERRNO(err)			((err) + HAL_ERROR_BASE)
#define EHAL_INVAL			_HAL_ERRNO(0)
#define EHAL_NOMEM 			_HAL_ERRNO(1)
#define EHAL_EXIST 			_HAL_ERRNO(2)

#define WIFI_ERROR_BASE 		320
#define _WIFI_ERRNO(err)		((err) + WIFI_ERROR_BASE)
#define EAP_ASSOC 			_WIFI_ERRNO(0)
#define EAP_INCORRECT 			_WIFI_ERRNO(1)
#define EAP_NOTFOUND 			_WIFI_ERRNO(2)
#define EAP_GETIP			_WIFI_ERRNO(3)
#define EAP_AUTH			_WIFI_ERRNO(4)
#define EAP_SCAN 			_WIFI_ERRNO(5)
#define EWIFI_EXIST 			_WIFI_ERRNO(6)
#define EWIFI_BUSY 			_WIFI_ERRNO(7)
#define EWIFI_UNOPEN 			_WIFI_ERRNO(8)
#define EWIFI_TIMEOUT 			_WIFI_ERRNO(9)
#define EWIFI_INT 			_WIFI_ERRNO(10)

#define MAX_ERRNO 			4095

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) 	__builtin_expect(!!(x), 0)
#define __must_check	__attribute__((warn_unused_result))
/* #define __force 	__attribute__((force)) */
#define __force

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline int __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline int __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#ifdef __cplusplus
}
#endif

#endif
