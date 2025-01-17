/**
 * linux-thread.h
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#define THIS_MODULE "HTHREAD"

#define _GNU_SOURCE
#include <hthread.h>
#include <log.h>

int hthread_create(pthread_t *tid, const char *name,
		void *(*fn)(void *), void *p)
{
	int ret;

	ret = pthread_create(tid, NULL, fn, p);
	if (ret != 0)
		return ret;

	if (!name)
		return 0;

	ret = pthread_setname_np(*tid, name);
	if (ret < 0)
		dprintf(2, "set pthread name %s error %d\n", name, ret);

	return 0;
}
