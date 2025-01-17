/**
 * pub-client.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 28, 2021
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <compiler.h>
#include <xbus.h>

struct msg_test {
	struct timespec	ts;
	int32_t id;
	char buf[256];
};

struct test_data {
	char topic[64];
	int prev_seq;
	int count;
	int target;
};

static int msg_handler(void *data, int len, void *p)
{
	struct msg_test *msg = data;
	struct test_data *td = p;
	struct timespec now;
	int seq;
	/* double dt; */

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* printf("msg id %d buf %s\n", msg->id, msg->buf); */
	sscanf(msg->buf, "pub %d", &seq);
	if (td->prev_seq == -1) {
		td->prev_seq = seq;
		return 0;
	}

	/* if (seq - prev_seq != 1) { */
	/*
	 * if (seq <= td->prev_seq) {
	 *         printf("received discontinuous id, id %d, prev id %d\n",
	 *                         seq, td->prev_seq);
	 *         exit(1);
	 * }
	 */
	td->prev_seq = seq;

	if ((td->count++ % 100) == 0)
		printf("%s id %d %s\n", td->topic, msg->id, msg->buf);
	/*
	 * dt = (now.tv_sec - msg->ts.tv_sec) * 1000.0;
	 * dt += (now.tv_nsec - msg->ts.tv_nsec) / 1000000.0;
	 */

	/* if (dt > 5) */

	return 0;
}

/* static int ack = 0; */

static int service_func(struct xbus_request *req, void *p)
{
	printf("req %s\n", req->req);

	printf("%s(%d)\n", __func__, __LINE__);
	memcpy(req->resp, req->req, req->resp_len);
	/* sprintf(req->response, "ack %d", ack++); */

	return 0;
}

static __used int test_service(int argc, char **argv)
{
	xbus_service("req", service_func, NULL);
	return 0;
}

static void notify(struct xbus_notification *mn, void *data)
{
	switch (mn->ev) {
	case XBUS_EVENT_NODE_OFFLINE:
		printf("Node %s is offline\n", mn->name);
		break;
	case XBUS_EVENT_NODE_ONLINE:
		printf("Node %s is online\n", mn->name);
		break;
	case XBUS_EVENT_SUB_OFFLINE:
		/* printf("Sub %s is offline\n", mn->name); */
		break;
	case XBUS_EVENT_SUB_ONLINE:
		printf("Sub %s is online\n", mn->name);
		break;
	case XBUS_EVENT_PUB_ONLINE:
		printf("Pub %s is online\n", mn->name);
		break;
	case XBUS_EVENT_PUB_OFFLINE:
		printf("Pub %s is offline\n", mn->name);
		break;
	default:
		break;
	}
}

static __used int test_notifier(struct xbus_notifier *ntf)
{
	int ret;

	ntf->func = notify;
	ret = xbus_register_notifier(ntf);
	if (ret < 0) {
		printf("register notifier error\n");
		return ret;
	}

	return 0;
}

static int test_pub(int argc, char **argv)
{
	struct msg_test msg;
	struct xbus_pub *pubs;
	struct test_data *tds;
	time_t t;
	char *buf;
	char topic[32] = {0};
	int pub_cnt = 1;
	int i = 0;
	int seq = 0;
	int ret;
	int size;

	if (argc > 1)
		pub_cnt = atoi(argv[1]);

	tds = malloc(pub_cnt * sizeof(struct test_data));
	for (i = 0; i < pub_cnt; i++) {
		memset(&tds[i], 0, sizeof(struct test_data));
		tds[i].prev_seq = -1;
		sprintf(tds[i].topic, "sub%d", i);
		xbus_subscribe(tds[i].topic, 512, msg_handler, &tds[i]);
	}

	srand((unsigned) time(&t));

	pubs = malloc(pub_cnt * sizeof(struct xbus_pub));
	if (pubs == NULL) {
		printf("No memory\n");
		return -1;
	}
	memset(pubs, 0, sizeof(struct xbus_pub) * pub_cnt);

	for (i = 0; i < pub_cnt; i++) {
		sprintf(topic, "ptopic%d", i);
		ret = xbus_pub_init(&pubs[i], topic, 128);
		if (ret < 0) {
			printf("init publisher error %d\n", ret);
			abort();
		}
	}

	while (1) {
		size = rand() % 64 + 1;
		/* size = 1024; */
		size *= 512;
		/* size = 4096; */
		buf = malloc(size);
		clock_gettime(CLOCK_MONOTONIC, &msg.ts);
		sprintf(msg.buf, "pub %d", seq++);
		printf("send %s\n", msg.buf);
		msg.id++;
		memcpy(buf, &msg, sizeof(msg));
		/* sprintf(buf, "pub %d", i++); */
		for (i = 0; i < pub_cnt; i++) {
			msg.id = i;
			ret = xbus_publish(&pubs[i], buf, size);
			/* printf("ret %d\n", ret); */
		}
		usleep(5000);
		/* sleep(1); */
		free(buf);
	}

	return 0;
}

static __used int test_shm(int argc, char **argv)
{
	struct xbus_shm_buf *sbuf;
	struct xbus_pub pub;
	struct timespec ts;
	uint32_t *p;
	int i = 0;
	int j = 0;

	xbus_pub_init(&pub, "pubshm", 10);

	xbus_pub_create_shm(&pub, 1048576, 16);

	/* test_sub(argc, argv); */

	while (1) {
		sbuf = xbus_pub_get_shmbuf(&pub, 0);
		if (sbuf == NULL) {
			printf("No free buf, sleep 100ms\n");
			/* abort(); */
			usleep(500000);
			continue;
		}
		p = sbuf->data;
		j = 0;
		for (i = 0; i < 1048576;) {
			p[j++] = rand();
			i += sizeof(uint32_t);
		}

		clock_gettime(CLOCK_MONOTONIC, &ts);
		/* xbus_log("sending %s\n", p); */

		xbus_publish(&pub, sbuf, sizeof(struct xbus_shm_buf));
		usleep(10000);
		/* sleep(1); */
	}

	return 0;
}

static __used int test_latency(int argc, char **argv)
{
	struct xbus_pub pub;
	struct timespec ts;
	char buf[512];
	char *p;
	int i = 0;

	xbus_pub_init(&pub, "latency", 10);

	/* test_sub(argc, argv); */

	while (1) {
		p = buf;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		sprintf(p, "shm %d", i++);
		memcpy(p + 16, &ts, sizeof(ts));

		xbus_publish(&pub, buf, sizeof(buf));
		usleep(10000);
		/* sleep(1); */
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct xbus_notifier ntf = {0};

	xbus_init("publish", 2);

	test_notifier(&ntf);
	/* test_shm(argc, argv); */
	/* test_pub(argc, argv); */
	/* test_pub_sanity(argc, argv); */
	test_shm(argc, argv);
	/* test_latency(argc, argv); */
	/* test_service(argc, argv); */
	while (1)
		sleep(3600);

	return 0;
}
