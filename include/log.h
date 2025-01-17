/**
 *   Copyright (C) 2020 All rights reserved.
 *
 *   FileName      ：log.h
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2020-07-10
 *   Description   ：
 */

#ifndef _HAL_LOG_H
#define _HAL_LOG_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG_ERR 	1
#define DEBUG_WARN 	2
#define DEBUG_INFO 	3
#define DEBUG_ALL 	4

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 	3
#endif

#ifndef LOG_TAG
#ifdef THIS_MODULE
#define LOG_TAG 	THIS_MODULE
#else
#define LOG_TAG 	"CORE"
#endif

#endif

#define dprintf(level, fmt, arg...) \
	do { \
		if (DEBUG_LEVEL >= level) \
			print("[%4s] " fmt , LOG_TAG, ##arg); \
	} while (0)

#define dbg(fmt, arg...) \
	do { \
		print("[%4s] %s(%d) " fmt "\n", LOG_TAG, __func__, __LINE__, ##arg); \
	} while (0)

#define check_ptr(ptr, fmt, arg...)					\
	if (ptr == NULL) {						\
		dprintf(1, fmt , ##arg);				\
		abort(); 						\
	}

void print(const char *fmt, ...);
void print_raw(const char *fmt, ...);
void log_file_open(const char *filename);
void log_file_close(void);

#ifdef __cplusplus
}
#endif
#endif
