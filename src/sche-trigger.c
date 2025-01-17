/**
 *   Copyright (C) 2021 All rights reserved.
 *
 *   FileName      ：sche-trigger.c
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2021-08-1
 *   Description   ：
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <log.h>
#include "sche.h"

#include "sche-trigger.h"

static void sche_trigger_handler(struct sche_unit *u)
{
	struct sche_trigger *t;
	char buf[16];
	int ret;

	t = (struct sche_trigger *)sche_unit_get_privdata(u);

	do {
		ret = read(t->sfd[1], buf, sizeof(buf));
	} while (ret >= sizeof(buf));

	t->action(t->priv);
}

struct sche_trigger *sche_trigger_alloc(struct sche *s, 
		const char *name,
		void (*action)(void *p), void *data)
{
	struct sche_trigger *trig;
	int flags;
	int ret;

	trig = (struct sche_trigger *)malloc(sizeof(struct sche_trigger));
	if (trig == NULL) {
		dprintf(1,"No memory for sche trigger\n");
		return NULL;
	}

	memset(trig, 0x00, sizeof(struct sche_trigger));

	ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, trig->sfd);
	if (ret < 0) {
		dprintf(1,"Can not create socket for tirgger\n");
		goto err_free_trig;
	}

	flags = fcntl(trig->sfd[0], F_GETFL, 0);
	if (flags < 0) {
		dprintf(1, "unable to get flags from fd\n");
		goto err_close_socket;
	}

	flags |= O_NONBLOCK;

	if (fcntl(trig->sfd[0], F_SETFL, flags) < 0) {
		dprintf(1, "unable to set flags for fd\n");
		goto err_close_socket;
	}

	sche_unit_set_privdata(&trig->unit, trig);

	/* sprintf(trig->unit.name, "trigger%d", trigger_count++); */
	strcpy(trig->unit.name, name);
	ret = sche_unit_register(s, &trig->unit, 
			trig->sfd[1], sche_trigger_handler);
	if (ret < 0) {
		dprintf(1,"Failed to register sche unit for trigger\n");
		goto err_close_socket;
	}

	trig->action = action;
	trig->priv = data;

	return trig;

err_close_socket:
	close(trig->sfd[0]);
	close(trig->sfd[1]);
err_free_trig:
	free(trig);

	return NULL;
}

void sche_trigger_release(struct sche_trigger *t)
{
	sche_unit_unregister(t->s, &t->unit);
	close(t->sfd[0]);
	close(t->sfd[1]);
	free(t);
}

void sche_trigger_on(struct sche_trigger *t)
{
	if (write(t->sfd[0], "t", 1) < 0)
		dprintf(1,"Failed to set trigger on\n");
}
