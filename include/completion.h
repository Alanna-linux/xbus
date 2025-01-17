/**
 * completion.h
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Apr 22, 2021
 *
 */

#ifndef _COMPLETION_H
#define _COMPLETION_H

#include <stdint.h>
#include <pthread.h>

struct completion {
	uint8_t 			wake;
	pthread_mutex_t 		mutex;
	pthread_condattr_t attr;
	pthread_cond_t			cond;
	int				action;
};

struct waker {
	uint8_t 			wake;
	pthread_mutex_t 		*mutex;
	pthread_condattr_t attr;
	pthread_cond_t			cond;
	uint8_t 			alloc_mutex;
	int				action;
};

int init_completion(struct completion *x);
void release_completion(struct completion *x);
void complete(struct completion *x);
void complete_all(struct completion *x);
void wait_for_completion(struct completion *x,
		int (*condition_func)(void *data), void *data);
int wait_for_completion_timeout(struct completion *x, int s,
			int (*condition_func)(void *data), void *data);

int init_waker(struct waker *x, pthread_mutex_t *mutex);
void release_waker(struct waker *x);
void waker_action(struct waker *x, int action);
void wait_for_action(struct waker *x, int action);
int wait_for_action_timeout(struct waker *x, int action, int s);

#endif
