/**
 * vref.c
 *
 * Copyright (C) 2024 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Apr 23, 2024
 *
 */

#include <vref.h>

int vref_put(struct vref *vref)
{
	if (vref->refcount > 0)
		vref->refcount--;
	if (vref->refcount == 0)
		vref->release(vref->user_data);

	return 0;
}

int vref_get(struct vref *vref)
{
	vref->refcount++;

	return 0;
}

int vref_init(struct vref *vref,
			void (*release)(void *p), void *p)
{
	pthread_mutex_init(&vref->mutex, NULL);
	vref->refcount = 0;
	vref->release = release;
	vref->user_data = p;

	return 0;
}

void vref_destroy(struct vref *vref)
{
	pthread_mutex_destroy(&vref->mutex);
}
