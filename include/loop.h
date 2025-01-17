/**
 *   Copyright (C) 2020 All rights reserved.
 *
 *   FileName      : loop.h
 *   Author        : zhujiongfu
 *   Email         : zhujiongfu@live.cn
 *   Date          : 2020-12-29
 *   Description   :
 */
#ifndef _LOOP_H
#define _LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
	EVENT_READABLE		= 0x01,
	EVENT_WRITABLE		= 0x02,
	EVENT_ET 		= 0x04,
	EVENT_HANGUP		= 0x08,
	EVENT_ERROR		= 0x10,
	EVENT_ONESHOT		= 0x20,
};

#ifdef __cplusplus
}
#endif

#endif
