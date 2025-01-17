/**
 * completion.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Apr 22, 2021
 *
 */

#define THIS_MODULE "COMPLETION"

#include <errno.h>
#include <wrapper.h>
#include <log.h>
#include <completion.h>

int init_completion(struct completion *x)
{
	pthread_condattr_t attr;
	int ret;

	ret = pthread_mutex_init(&x->mutex, NULL);
	if (ret != 0) {
		dprintf(1, "init mutex error\n");
		return -1;
	}

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	ret = pthread_cond_init(&x->cond, &attr);
	if (ret != 0) {
		dprintf(1, "init cond error\n");
		pthread_mutex_destroy(&x->mutex);
		return -1;
	}
	x->wake = 0;

	return 0;
}

void release_completion(struct completion *x)
{
	pthread_cond_destroy(&x->cond);
	pthread_condattr_destroy(&x->attr);
	pthread_mutex_destroy(&x->mutex);
}

void complete(struct completion *x)
{
	pthread_mutex_lock(&x->mutex);
	if (x->wake == 0) {
		pthread_mutex_unlock(&x->mutex);
		return;
	}
	pthread_cond_signal(&x->cond);
	pthread_mutex_unlock(&x->mutex);
}

void complete_all(struct completion *x)
{
	pthread_mutex_lock(&x->mutex);
	if (x->wake == 0) {
		pthread_mutex_unlock(&x->mutex);
		return;
	}
	pthread_cond_broadcast(&x->cond);
	pthread_mutex_unlock(&x->mutex);
}

void wait_for_completion(struct completion *x,
		int (*condition_func)(void *data), void *data)
{
	if (condition_func) {
		for (;;) {
			if (condition_func(data))
				break;
			pthread_mutex_lock(&x->mutex);
			x->wake++;
			pthread_cond_wait(&x->cond, &x->mutex);
			x->wake--;
			pthread_mutex_unlock(&x->mutex);
		}
	} else {
		pthread_mutex_lock(&x->mutex);
		x->wake++;
		pthread_cond_wait(&x->cond, &x->mutex);
		x->wake--;
		pthread_mutex_unlock(&x->mutex);
	}
}

int wait_for_completion_timeout(struct completion *x, int s,
			int (*condition_func)(void *data), void *data)
{
	struct timespec timeout;
	int ret = 0;

	clock_gettime(CLOCK_MONOTONIC, &timeout);
	timeout.tv_sec += s;

	if (condition_func) {
		for (;;) {
			if (condition_func(data))
				break;
			pthread_mutex_lock(&x->mutex);
			x->wake++;
			ret = pthread_cond_timedwait(&x->cond,
						&x->mutex, &timeout);
			x->wake--;
			pthread_mutex_unlock(&x->mutex);
			if (ret != 0)
				break;
		}
	} else {
		pthread_mutex_lock(&x->mutex);
		x->wake++;
		ret = pthread_cond_timedwait(&x->cond, &x->mutex, &timeout);
		x->wake--;
		pthread_mutex_unlock(&x->mutex);
	}

	return ret == 0 ? 0 : -ret;
}

int init_waker(struct waker *x, pthread_mutex_t *mutex)
{
	int ret;

	if (mutex == NULL) {
		x->mutex = xzmalloc(sizeof(pthread_mutex_t));
		check_ptr(x->mutex, "No memory for waker mutex\n");
		x->alloc_mutex = 1;
		ret = pthread_mutex_init(x->mutex, NULL);
		if (ret != 0) {
			dprintf(1, "init mutex error\n");
			return -1;
		}
	} else {
		x->mutex = mutex;
	}

	pthread_condattr_init(&x->attr);
	pthread_condattr_setclock(&x->attr, CLOCK_MONOTONIC);
	ret = pthread_cond_init(&x->cond, &x->attr);
	if (ret != 0) {
		dprintf(1, "init cond error\n");
		return -1;
	}
	x->wake = 0;

	return 0;
}

void release_waker(struct waker *x)
{
	pthread_cond_destroy(&x->cond);
	pthread_condattr_destroy(&x->attr);
	pthread_mutex_destroy(x->mutex);
	if (x->alloc_mutex)
		xfree(x->mutex);
}

void waker_action(struct waker *x, int action)
{
	pthread_mutex_lock(x->mutex);
	x->action = action;
	pthread_mutex_unlock(x->mutex);
	pthread_cond_signal(&x->cond);
}

void wait_for_action(struct waker *x, int action)
{
	pthread_mutex_lock(x->mutex);
	for (;;) {
		if (x->action == action)
			break;
		x->wake++;
		pthread_cond_wait(&x->cond, x->mutex);
		x->wake--;
	}
	x->action = 0;
	pthread_mutex_unlock(x->mutex);
}

int wait_for_action_timeout(struct waker *x, int action, int s)
{
	struct timespec timeout;
	int ret = 0;

	pthread_mutex_lock(x->mutex);
	clock_gettime(CLOCK_MONOTONIC, &timeout);
	timeout.tv_sec += s;
	for (;;) {
		if (x->action == action)
			break;
		x->wake++;
		ret = pthread_cond_timedwait(&x->cond,
					x->mutex, &timeout);
		x->wake--;
		if (ret != 0)
			break;
	}
	x->action = 0;
	pthread_mutex_unlock(x->mutex);

	return ret == 0 ? 0 : -ret;
}

