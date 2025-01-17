/**
 *   Copyright (C) 2019 All rights reserved.
 *
 *   FileName      ：fifo.h
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2019-09-02
 *   Description   ：
 */

#ifndef _FIFO_H
#define _FIFO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

struct fifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	void *data;
};

#define fifo_out_lock(f, buf, len, lock)				\
({									\
	unsigned int __ret;						\
	pthread_mutex_lock(lock);					\
	__ret = fifo_out(f, buf, len);					\
	pthread_mutex_unlock(lock);					\
	__ret;								\
})

#define fifo_in_lock(fifo, buf, len, lock)				\
({									\
	unsigned int __ret;						\
	pthread_mutex_lock(lock);					\
	__ret = fifo_in(fifo, buf, len);				\
	pthread_mutex_unlock(lock);					\
	__ret;								\
})

#define fifo_prefetch_lock(fifo, rlen, lock)				\
({									\
	void *__ret;							\
	pthread_mutex_lock(lock);					\
	__ret = fifo_prefetch(fifo, rlen);				\
	pthread_mutex_unlock(lock);					\
	__ret;								\
})

#define fifo_fetched_lock(fifo, len, lock)				\
({									\
	pthread_mutex_lock(lock);					\
	(fifo)->out += len; 						\
	pthread_mutex_unlock(lock);					\
})

#define fifo_len(fifo)							\
({									\
	(fifo)->in - (fifo)->out;					\
})

int fifo_init(struct fifo *fifo, size_t size);
void fifo_release(struct fifo *fifo);
unsigned int fifo_in(struct fifo *fifo, 
			const void *buf, unsigned int len);
unsigned int fifo_out(struct fifo *fifo, void *dst, unsigned int len);
void *fifo_prefetch(struct fifo *fifo, unsigned int *rlen);
unsigned int fifo_unused(struct fifo *fifo);

#ifdef __cplusplus
}
#endif

#endif
