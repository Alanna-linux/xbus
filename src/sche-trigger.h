/**
 *   Copyright (C) 2021 All rights reserved.
 *
 *   FileName      ：sche-trigger.h
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2021-08-1
 *   Description   ：
 */

#ifndef _SCHE_TRIGGER_H
#define _SCHE_TRIGGER_H

#include "sche.h"

struct sche_trigger {
	struct sche *s;
	struct sche_unit unit;
	void (*action)(void *p);
	int sfd[2];
	int efd;
	void *priv;
};

struct sche_trigger *sche_trigger_alloc(struct sche *s, 
		const char *name, 
		void (*action)(void *p), void *data);
void sche_trigger_on(struct sche_trigger *t);
void sche_trigger_release(struct sche_trigger *t);

#endif

