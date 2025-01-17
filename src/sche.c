/**
 *   Copyright (C) 2021 All rights reserved.
 *
 *   FileName      ：sche.c
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2021-08-1
 *   Description   ：
 */

#define THIS_MODULE 	"SCHE"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include <utils.h>
#include <log.h>
#include <event-loop.h>
#include <wrapper.h>
#include <bitops.h>
#include <error.h>

#include "sche.h"

#define SCHE_SOURCE_ONESHOT	BIT(0)

#define SCHE_WORKER_ONESHOT	BIT(0)

static struct sche_event *sche_event_create()
{
	struct sche_event *event;

	event = (struct sche_event *)xmalloc(sizeof(struct sche_event));
	if (event == NULL) {
		dprintf(1,"No memeory for sche event\n");
		return NULL;
	}

	event->eloop = event_loop_create();
	if (IS_ERR_OR_NULL(event->eloop)) {
		dprintf(1, "create event loop error\n");
		xfree(event);
		return NULL;
	}

	INIT_LIST_HEAD(&event->list_sources);
	event->fd = 0;

	return event;
}

static void sche_event_release(struct sche_event *e)
{
	event_loop_destroy(e->eloop);
	xfree(e);
}

static int sche_event_handler(int fd, unsigned int mask, void *data)
{
	struct sche_source *s = data;

	return s->action(s->fd, mask, s->priv);
}

static int sche_add_source(struct sche_event *e, struct sche_source *s)
{
	list_add(&s->source_node, &e->list_sources);

	s->es = event_loop_add_fd(e->eloop, s->fd,
			s->flag, sche_event_handler, s);
	if (s->es == NULL) {
		dprintf(1, "add fd to event loop error\n");
		return -1;
	}
	s->id = s->es->fd;
	dprintf(1, "sche id %d\n", s->id);

	return s->id;
}

static void sche_del_source(struct sche_event *e, struct sche_source *s)
{
	list_del(&s->source_node);

	event_source_remove(s->es);
}

static int sche_event_add_fd(struct sche_event *e,
		const int fd, uint32_t mask, 
		int (*event_action)(int fd, uint32_t mask, void *p),
		void *data)
{
	struct sche_source *s;

	s = (struct sche_source *)xmalloc(sizeof(struct sche_source));
	if (s == NULL) {
		dprintf(1,"No memory for sche source\n");
		return -ENOMEM;
	}
	memset(s, 0x00, sizeof(struct sche_source));

	s->fd = fd;
	s->action = event_action;
	s->priv = data;
	if (mask)
		s->flag = mask;
	else
		s->flag = EVENT_READABLE;
	INIT_LIST_HEAD(&s->source_node);

	if (fd >= e->fd)
		e->fd = fd + 1;

	return sche_add_source(e, s);
}

static void sche_event_del_fd(struct sche_event *e, int fd)
{
	struct sche_source *s;

	list_for_each_entry(s, &e->list_sources, source_node) {
		if (s->fd != fd)
			continue;

		break;
	}

	sche_del_source(e, s);

	xfree(s);
}

static int sche_event_dispatch(struct sche_event *e, int timeout)
{
	struct timeval tv_start, tv_end;
	int ret;

	gettimeofday(&tv_start, NULL);
	ret = event_loop_dispatch(e->eloop, timeout);
	if (ret < 0) {
		dprintf(1, "event loop dispatchs error\n");
		return -1;
	}
	gettimeofday(&tv_end, NULL);

	/*
	 * time = (tv_end.tv_sec - tv_start.tv_sec) * 1000000
	 *         + tv_end.tv_usec - tv_start.tv_usec;
	 */
	/* printf("loop time: %dus\n", time); */
	return 0;
}

static int sync_notify_init(struct sync_notify *n)
{
	int fd[2];
	int flags;
	int ret;

	ret = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, fd);
	if (ret < 0) {
		perror("Failed to create socketpair");
		return ret;
	}

	n->send_fd = fd[0];
	n->wait_fd = fd[1];
	n->pfd.events = POLLIN;
	n->pfd.fd = n->wait_fd;

	flags = fcntl(n->wait_fd, F_GETFL, 0);
	if (flags < 0) {
		dprintf(1, "unable to get flags from fd\n");
		goto err_close_socket;
	}

	flags |= O_NONBLOCK;

	if (fcntl(n->wait_fd, F_SETFL, flags) < 0) {
		dprintf(1, "unable to set flags for fd\n");
		goto err_close_socket;
	}

	return 0;

err_close_socket:
	close(n->send_fd);
	close(n->wait_fd);

	return -1;
}

static void sync_notify_release(struct sync_notify *n)
{
	close(n->send_fd);
	close(n->wait_fd);
}

static void sync_notify_wait(struct sync_notify *n, int timeout)
{
	char buf[16];
	int ret;

	if (poll(&n->pfd, 1, timeout) < 0) {
		return;
	}

	if (n->pfd.revents & POLLIN) {
		do {
			ret = read(n->pfd.fd, buf, sizeof(buf));
		} while (ret >= sizeof(buf));
	}
}

static void sync_notify_send(struct sync_notify *n)
{
	write(n->send_fd, "st", 2);
}

static void worker_send_notify(struct worker *w)
{
	if (w->flag & SCHE_WORKER_ONESHOT)
		return;
	pthread_mutex_lock(&w->mutex_worker);

	if (w->status == WORKER_STATUS_WAIT)
		sync_notify_send(&w->notify);

	pthread_mutex_unlock(&w->mutex_worker);
}

static void worker_wait_notify(struct worker *w, int timeout)
{
	if (w->flag & SCHE_WORKER_ONESHOT)
		return;
	
	sync_notify_wait(&w->notify, timeout);	

	pthread_mutex_lock(&w->mutex_worker);

	w->status = WORKER_STATUS_RUNNING;

	pthread_mutex_unlock(&w->mutex_worker);
}

static void sche_unit_run(struct sche_unit *u)
{
	struct timeval st, et;
	int t = 0;

	gettimeofday(&st, NULL);

	if (u->tv.tv_sec != 0) {
		t = st.tv_sec * 1000000 + st.tv_usec 
			- u->tv.tv_sec * 1000000 
			- u->tv.tv_usec;
	}

	pthread_mutex_lock(&u->mutex_unit);
	u->idletime = t;
	u->run_timestamp = st;
	t = (u->run_timestamp.tv_sec 
		- u->queue_timestamp.tv_sec) * 1000000L;
	t += u->run_timestamp.tv_usec - 
			u->queue_timestamp.tv_usec;
	u->wait_time = t;
	pthread_mutex_unlock(&u->mutex_unit);

	dprintf(4, "unit %s idletime: %d wait_time: %d\n", 
			u->name, u->idletime, u->wait_time);
	u->handler(u);

	gettimeofday(&et, NULL);
	u->tv = et;
	
	t = (et.tv_sec - st.tv_sec) * 1000000L;
	t += et.tv_usec - st.tv_usec;

	pthread_mutex_lock(&u->mutex_unit);
	if (u->balance == 0)
		u->balance = t;
	else
		u->balance = (u->balance + t) / 2.0;
	pthread_mutex_unlock(&u->mutex_unit);

	dprintf(4,"unit %s runtime: %d\n", u->name, u->balance);
}

static void *worker_run(void *arg)
{
	struct worker *w = (struct worker *)arg;
	struct sche_unit *unit, *tmp;

	if (w->flag & SCHE_WORKER_ONESHOT)
		sleep(1);
	for (;;) {
		pthread_mutex_lock(&w->mutex_worker);
		w->status = WORKER_STATUS_WAIT;
		pthread_mutex_unlock(&w->mutex_worker);

		worker_wait_notify(w, -1);

		pthread_mutex_lock(&w->mutex_queue);
		list_for_each_safe(unit, tmp, &w->run_queue, worker_node) {
			if (!(unit->flag & SCHE_UNIT_ONESHOT )) {
				w->num_tasks--;
				list_del(&unit->worker_node);
			}
			pthread_mutex_unlock(&w->mutex_queue);

			/* printf("unit: %s\n", unit->name); */
			sche_unit_run(unit);
		
			pthread_mutex_lock(&w->mutex_worker);
			if (w->wait_time > unit->balance)
				w->wait_time -= unit->balance;
			else
				w->wait_time = 0;
			pthread_mutex_unlock(&w->mutex_worker);

			pthread_mutex_lock(&unit->mutex_unit);
			unit->run_status = SCHE_UNIT_STATUS_RUNNABLE;
			pthread_mutex_unlock(&unit->mutex_unit);

			pthread_mutex_lock(&w->mutex_queue);
		}
		pthread_mutex_unlock(&w->mutex_queue);

		if (w->unit == NULL)
			continue;

		pthread_mutex_lock(&w->mutex_worker);
		if (w->max_balance != 0 && w->unit->idletime < w->max_balance)
			w->max_balance = w->unit->idletime;
		else
			w->max_balance = w->unit->idletime;
		w->wait_time += w->unit->balance;
		gettimeofday(&w->unit->queue_timestamp, NULL);
		pthread_mutex_unlock(&w->mutex_worker);
	}

	return (void *)0;
}

static int worker_add_task(struct worker *worker, struct sche_unit *unit)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	pthread_mutex_lock(&worker->mutex_queue);
	worker->num_tasks++;
	list_add_tail(&unit->worker_node, &worker->run_queue);
	pthread_mutex_unlock(&worker->mutex_queue);

	pthread_mutex_lock(&worker->mutex_worker);
	worker->wait_time += unit->balance;
	pthread_mutex_unlock(&worker->mutex_worker);

	/* printf("10unit: %s\n", unit->name); */
	dprintf(4,"worker %d add unit %s\n", worker->id, unit->name);
	pthread_mutex_lock(&unit->mutex_unit);
	unit->run_status = SCHE_UNIT_STATUS_RUNNING;
	unit->queue_timestamp = tv;
	pthread_mutex_unlock(&unit->mutex_unit);

	return 0;
}

static struct worker *worker_create(struct sche *sche, int flag)
{
	struct worker *worker;
	int ret;

	worker = (struct worker *)xmalloc(sizeof(struct worker));
	if (worker == NULL) {
		dprintf(1,"No memory for worker\n");
		
		return NULL;
	}
	memset(worker, 0x00, sizeof(struct worker));

	ret = sync_notify_init(&worker->notify);
	if (ret < 0) {
		dprintf(1,"failed to init notify\n");
		goto err_free_worker;
	}

	pthread_mutex_init(&worker->mutex_worker, NULL);
	pthread_mutex_init(&worker->mutex_queue, NULL);
	INIT_LIST_HEAD(&worker->run_queue);
	INIT_LIST_HEAD(&worker->sche_node);
	worker->num_tasks = 0;
	worker->status = WORKER_STATUS_WAIT;
	worker->flag = flag;
	/* set unit allowed balance to max */
	if (flag & SCHE_WORKER_ONESHOT) {
		worker->max_balance = 0;
		worker->wait_time = 0x1000000;
	} else {
		worker->max_balance = 0x0fffffff;
	}

	list_add(&worker->sche_node, &sche->list_workers);

	worker->id = sche->num_wokers;

	ret = pthread_create(&worker->tid, NULL, worker_run, worker);
	if (ret != 0) {
		dprintf(1,"failed to create worker thread\n");
		goto err_notify_release;
	}

	dprintf(3,"Created the %d worker\n", sche->num_wokers);
	sche->num_wokers++;

	return worker;

err_notify_release:
	sync_notify_release(&worker->notify);
err_free_worker:
	xfree(worker);

	return NULL;
}

static struct worker *sche_find_best_worker(struct sche *sche, 
		struct sche_unit *u)
{
	struct worker *worker = NULL, *best = NULL;
	int idletime = u->idletime;
	int found = 0;

	if (sche->num_wokers == 0)
		return worker_create(sche, 0);

	dprintf(4,"unit: %s\n ", u->name);
	list_for_each_entry(worker, &sche->list_workers, sche_node) {
		pthread_mutex_lock(&worker->mutex_worker);

		/*
		 * if (worker->flag & SCHE_WORKER_ONESHOT) {
		 *         pthread_mutex_unlock(&worker->mutex_worker);
		 *         continue;
		 * }
		 */

		if (best == NULL)
			best = worker;

		dprintf(4,"worker %d max_balance: %d u: %d\n", 
				worker->id, worker->max_balance, u->balance);
		if (worker->wait_time <= best->wait_time && 
				worker->max_balance >= u->balance)
			best = worker;

		dprintf(4,"worker %d wait: %d, unit idle: %d\n", 
				worker->id, worker->wait_time, idletime);
		if (worker->wait_time > idletime) {
			pthread_mutex_unlock(&worker->mutex_worker);
			continue;
		}

		found = 1;

		pthread_mutex_unlock(&worker->mutex_worker);
	}

	if (found || sche->num_wokers > sche->max_workers)
		return best;

	return worker_create(sche, 0);
}

static int sche_find_unit_min_idletime(struct sche *s)
{
	struct sche_unit *u;
	int min = 0;

	list_for_each_entry(u, &s->list_units, sche_node) {
		if (u->flag & SCHE_UNIT_ONESHOT)
			continue;
		pthread_mutex_lock(&u->mutex_unit);
		if (min == 0 && u->idletime != 0) {
			min = u->idletime;
			pthread_mutex_unlock(&u->mutex_unit);
			continue;
		}

		if (u->idletime != 0 && u->idletime < min)
			min = u->idletime;
		pthread_mutex_unlock(&u->mutex_unit);
	}

	if (s->unit_idle_min_time != 0 && 
			s->unit_idle_min_time > min)
		min = s->unit_idle_min_time;

	return min;
}

static int sche_event_action(int fd, uint32_t mask, void *data)
{
	struct sche *sche = (struct sche *)data;
	struct worker *worker;
	struct sche_unit *unit;
	enum sche_unit_status status;

	list_for_each_entry(unit, &sche->list_units, sche_node)
		if (unit->fd == fd)
			break;

	if (unit->flag & SCHE_UNIT_ONESHOT) {
		worker = worker_create(sche, SCHE_WORKER_ONESHOT);
		check_ptr(worker, "can not create oneshot worker\n");
		worker->unit = unit;
		worker_add_task(worker, unit);
		return 0;
	}

	pthread_mutex_lock(&unit->mutex_unit);
	status = unit->run_status;
	pthread_mutex_unlock(&unit->mutex_unit);

	/*
	 * if (!strcmp(unit->name, "imu")) {
	 *         gettimeofday(&unit->queue_timestamp, NULL);
	 *         sche_unit_run(unit);
	 *         return 0;
	 * }
	 */
	sche->unit_idle_min_time = sche_find_unit_min_idletime(sche);
	if (unit->balance < sche->unit_idle_min_time && 
			status == SCHE_UNIT_STATUS_RUNNABLE) {
		dprintf(4,"unit %s handle in sche thread\n", unit->name);
		/* unit->handler(unit); */
		gettimeofday(&unit->queue_timestamp, NULL);

		sche_unit_run(unit);

		pthread_mutex_lock(&unit->mutex_unit);
		unit->run_status = SCHE_UNIT_STATUS_RUNNABLE;
		pthread_mutex_unlock(&unit->mutex_unit);

		return 0;
	}

	if (status == SCHE_UNIT_STATUS_RUNNABLE) {
		worker = sche_find_best_worker(sche, unit);
		worker_add_task(worker, unit);
		dprintf(4,"unit: %s, worker id:%d, fd: %d\n", 
				unit->name, worker->id, fd);
		worker_send_notify(worker);
	}

	return 0;
}

void sche_run(struct sche *s, int timeout)
{
	for (;;)
		sche_event_dispatch(s->event, timeout);
}

int sche_run_onece(struct sche *s, int timeout)
{
	return sche_event_dispatch(s->event, timeout);
}

void sche_unit_set_privdata(struct sche_unit *u, void *data)
{
	u->priv = data;
}

void *sche_unit_get_privdata(struct sche_unit *u)
{
	return u->priv;
}

int sche_add_fd(struct sche *s, int fd, uint32_t mask,
		int (*handler)(int fd, uint32_t mask, void *p), void *data)
{
	int ret = 0;

	pthread_mutex_lock(&s->mutex_sche);
	ret = sche_event_add_fd(s->event, fd, mask, handler, data);
	pthread_mutex_unlock(&s->mutex_sche);
	if (ret < 0)
		dprintf(1,"can not add fd to sche\n");

	return ret;
}

int sche_fd_update(struct sche *s, int id, uint32_t mask)
{
	struct sche_source *src;
	int found = 0;

	pthread_mutex_lock(&s->mutex_sche);
	list_for_each_entry(src, &s->event->list_sources, source_node) {
		if (src->id == id) {
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&s->mutex_sche);

	if (found == 0)
		return -ENOENT;

	return event_source_fd_update(src->es, mask);
}

int sche_rm_id(struct sche *s, int id)
{
	struct sche_source *src;
	int found = 0;

	pthread_mutex_lock(&s->mutex_sche);
	list_for_each_entry(src, &s->event->list_sources, source_node) {
		if (src->id == id) {
			found = 1;
			break;
		}
	}

	if (found == 0) {
		pthread_mutex_unlock(&s->mutex_sche);
		return -ENOENT;
	}

	sche_del_source(s->event, src);
	xfree(src);
	pthread_mutex_unlock(&s->mutex_sche);

	return 0;
}

void sche_rm_fd(struct sche *s, int fd)
{
	pthread_mutex_lock(&s->mutex_sche);
	sche_event_del_fd(s->event, fd);
	pthread_mutex_unlock(&s->mutex_sche);
}

int sche_unit_register(struct sche *s, struct sche_unit *unit, int fd, 
		sche_handler_func_t func)
{
	int ret;
	
	pthread_mutex_lock(&s->mutex_sche);

	ret = sche_event_add_fd(s->event, fd, unit->flag, 
					sche_event_action, s);
	if (ret < 0) {
		dprintf(1,"can not add fd to event loop\n");
		pthread_mutex_unlock(&s->mutex_sche);
		return -1;
	}

	unit->fd = fd;
	unit->handler = func;
	unit->idletime = 0;
	unit->balance = 0;
	unit->run_status = SCHE_UNIT_STATUS_RUNNABLE;

	pthread_mutex_init(&unit->mutex_unit, NULL);
	INIT_LIST_HEAD(&unit->sche_node);
	list_add(&unit->sche_node, &s->list_units);
	s->num_units++;

	pthread_mutex_unlock(&s->mutex_sche);

	return 0;
}

void sche_unit_unregister(struct sche *s, struct sche_unit *u)
{
	pthread_mutex_destroy(&u->mutex_unit);
	
	pthread_mutex_lock(&s->mutex_sche);
	list_del(&u->sche_node);
	sche_event_del_fd(s->event, u->fd);
	pthread_mutex_unlock(&s->mutex_sche);
}

struct sche *sche_alloc(const char *name)
{
	struct sche *s;

	s = (struct sche *)xmalloc(sizeof(struct sche));
	if (s == NULL) {
		dprintf(1,"No memory for scheduler\n");
		return NULL;
	}

	strcpy(s->name, name);
	s->num_units = 0;
	s->num_wokers = 0;
	s->max_workers = 1;
	INIT_LIST_HEAD(&s->list_units);
	INIT_LIST_HEAD(&s->list_workers);

	pthread_mutex_init(&s->mutex_sche, NULL);

	s->event = sche_event_create();
	if (s->event == NULL) {
		dprintf(1,"can not create sche event\n");
		goto err_free_sche;
	}

	return s;

err_free_sche:
	xfree(s);

	return NULL;
}

void sche_release(struct sche *s)
{
	struct sche_unit *u;

	list_for_each_entry(u, &s->list_units, sche_node)
		sche_event_del_fd(s->event, u->fd);

	sche_event_release(s->event);
	s->event = NULL;
	pthread_mutex_destroy(&s->mutex_sche);

	xfree(s);
}
