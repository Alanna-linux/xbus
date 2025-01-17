#ifndef _EVENT_LOOP_H
#define _EVENT_LOOP_H

#include <pthread.h>
#include <sys/epoll.h>
#include <utils.h>
#include "loop.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int event_loop_fd_func_t(int fd, uint32_t mask, void *data);
typedef int event_loop_signal_func_t(int signal_number, void *data);

struct event_loop {
	struct list_head 			destroy_list;
	int					epoll_fd;
};

struct event_source {
	struct list_head			link;
	struct event_source_interface		*interface;
	struct event_loop			*loop;
	void					*data;
	int					fd;
};

struct event_source_interface {
	int (*dispatch)(struct event_source *source,
			struct epoll_event *ep);
};

struct event_source *event_loop_add_fd(struct event_loop *loop,
				int fd, uint32_t mask,
				event_loop_fd_func_t *func,
				void *data);
int event_source_fd_update(struct event_source *source, uint32_t mask);
struct event_loop *event_loop_create(void);
void event_loop_destroy(struct event_loop *loop);
int epoll_create_cloexec(void);
void event_source_remove(struct event_source *source);
int event_loop_dispatch(struct event_loop *loop, int timeout);
struct event_source *event_loop_add_signal(struct event_loop *loop,
			int signal_number,
			event_loop_signal_func_t *func, void *data);

#ifdef __cplusplus
}
#endif

#endif
