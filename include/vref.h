/**
 * vref.h
 *
 * Copyright (C) 2024 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Apr 23, 2024
 *
 */

#ifndef _VREF_H
#define _VREF_H

#include <pthread.h>

struct vref {
	pthread_mutex_t mutex;
	int refcount;
	void (*release)(void *p);
	void *user_data;
};

int vref_init(struct vref *vref,
			void (*release)(void *p), void *p);
void vref_destroy(struct vref *vref);
int vref_get(struct vref *vref);
int vref_put(struct vref *vref);

#endif
