/**
 * inner-client.c
 *
 * Copyright (C) 2022 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 27, 2022
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <compiler.h>
#include <xbus.h>
#include <log.h>

struct msg_test {
	struct timespec	ts;
	int32_t id;
	char buf[256];
};

static int msg_handler(void *data, int len, void *p)
{
	struct msg_test *msg = data;
	int id = (int)p;

	printf("id %d %s\n", id, msg->buf);

	return 0;
}

int main(int argc, char **argv)
{
	struct msg_test msg;
	struct xbus_pub pub;
	struct xbus_pub pub1;
	int seq = 0;

	xbus_init("sub", 1);

	xbus_pub_init(&pub, "ptopic0", 32);
	xbus_pub_init(&pub1, "ptopic0", 32);
	xbus_subscribe("ptopic0", 16, msg_handler, 0);
	xbus_subscribe("ptopic0", 16, msg_handler, (void *)1);

	while (1) {
		sprintf(msg.buf, "pub0 %d", seq++);
		xbus_publish(&pub, &msg, sizeof(msg));
		sprintf(msg.buf, "pub1 %d", seq++);
		xbus_publish(&pub1, &msg, sizeof(msg));
		sleep(1);
	}

	return 0;
}
