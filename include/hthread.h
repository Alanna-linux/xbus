/**
 * hthread.h
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#ifndef _HTHREAD_H
#define _HTHREAD_H

#include <pthread.h>

int hthread_create(pthread_t *tid, const char *name,
		void *(*fn)(void *), void *p);

#endif
