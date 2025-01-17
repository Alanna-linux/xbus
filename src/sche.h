/**
 *   Copyright (C) 2021 All rights reserved.
 *
 *   FileName      ：sche.h
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2021-08-1
 *   Description   ：
 */

#ifndef _SCHE_H
#define _SCHE_H

#include <stdio.h>
#include <sys/time.h>
#include <poll.h>
#include <pthread.h>

#include <event-loop.h>
#include "utils.h"

enum worker_status {
	WORKER_STATUS_WAIT = 0,
	WORKER_STATUS_RUNNING,
};

struct sync_notify {
	struct pollfd pfd;
	int send_fd;
	int wait_fd;
};

struct worker {
	int id;
	pthread_mutex_t	mutex_worker;
	pthread_t tid;
	int num_tasks;
	int flag;
	
	pthread_mutex_t	mutex_queue;
	struct list_head run_queue;
	struct list_head sche_node;

	enum worker_status status;
	int wait_time;
	int max_balance;
	struct sche_unit *unit;

	struct sync_notify notify;
};

struct sche_source {
	struct list_head source_node;
	struct event_source *es;
	int fd;
	int id;
	uint32_t flag;
	int (*action)(int fd, uint32_t mask, void *p);
	void *priv;
};

struct sche_event {
	int fd;
	struct event_loop *eloop;
	struct list_head list_sources;
};

struct sche {
	pthread_mutex_t mutex_sche;

	int num_units;
	struct list_head list_units;
	int num_wokers;
	int max_workers;
	struct list_head list_workers;

	int unit_idle_min_time;

	struct sche_event *event;
	char name[32];
};


struct sche_unit;
typedef void (*sche_handler_func_t)(struct sche_unit *unit);

#define SCHE_UNIT_ONESHOT	BIT(0)

enum sche_unit_status {
	SCHE_UNIT_STATUS_RUNNABLE = 0,
	SCHE_UNIT_STATUS_RUNNING,
};

struct sche_unit {
	pthread_mutex_t mutex_unit;
#define SCHE_NAME_SIZE	32
	char name[SCHE_NAME_SIZE];
	struct list_head sche_node;
	struct list_head worker_node;

	int fd;
	enum sche_unit_status run_status;

	int balance;
	int idletime;
	int wait_time;
	struct timeval queue_timestamp;
	struct timeval run_timestamp;
	struct timeval tv;;
	sche_handler_func_t handler;

	int flag;

	void *priv;
	void *sche;
};

struct sche *sche_alloc(const char *name);
void sche_run(struct sche *s, int timeout);
int sche_run_onece(struct sche *s, int timeout);
void sche_unit_set_privdata(struct sche_unit *u, void *data);
void *sche_unit_get_privdata(struct sche_unit *u);
int sche_unit_register(struct sche *s, struct sche_unit *unit, int fd, 
		sche_handler_func_t func);
void sche_unit_unregister(struct sche *s, struct sche_unit *u);
int sche_add_fd(struct sche *s, int fd, uint32_t mask,
		int (*handler)(int fd, uint32_t mask, void *p), void *data);
int sche_fd_update(struct sche *s, int id, uint32_t mask);
void sche_rm_fd(struct sche *s, int fd);
int sche_rm_id(struct sche *s, int id);
void sche_release(struct sche *s);

#endif
