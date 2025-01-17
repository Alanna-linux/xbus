/**
 * sub-client.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 28, 2021
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#include <compiler.h>
#include <xbus.h>
#include <log.h>

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

static int shm_msg_handler(void *data, int len, void *p)
{
	struct timespec ts;
	struct timespec now;
	char *str = data;
	double dt;

	memcpy(&ts, str + 16, sizeof(ts));
	clock_gettime(CLOCK_MONOTONIC, &now);
	/* xbus_log("received %s\n", str); */

	dt = (now.tv_sec - ts.tv_sec) * 1000.0;
	dt += (now.tv_nsec - ts.tv_nsec) / 1000000.0;

	printf("cost time %lf(ms)\n", dt);

	return 0;
}

static int onoff_msg_handler(void *data, int len, void *p)
{
	struct msg_test *msg = data;
	struct test_data *td = p;
	int seq;

	printf("topic %s target %d count %d id %d %s\n",
			td->topic, td->target,
			td->count, msg->id, msg->buf);
	sscanf(msg->buf, "pub %d", &seq);
	if (seq <= td->prev_seq) {
		printf("received discontinuous id, id %d, prev id %d\n",
				seq, td->prev_seq);
		exit(1);
	}
	td->prev_seq = seq;

	if (td->count++ > td->target)
		exit(0);

	return 0;
}

static int msg_handler(void *data, int len, void *p)
{
	struct msg_test *msg = data;
	struct test_data *td = p;
	struct timespec now;
	int seq;
	/* double dt; */

	/* return 0; */
	clock_gettime(CLOCK_MONOTONIC, &now);

	sscanf(msg->buf, "pub %d", &seq);
	if (td->prev_seq == -1) {
		td->prev_seq = seq;
		return 0;
	}

	printf("msg id %d buf %s\n", msg->id, msg->buf);
	/* if (seq - prev_seq != 1) { */
	if (seq <= td->prev_seq) {
		/* printf("msg id %d buf %s\n", msg->id, msg->buf); */
		printf("received discontinuous id, id %d, prev id %d\n",
				seq, td->prev_seq);
		exit(1);
	}
	td->prev_seq = seq;

	if ((td->count++ % 100) == 0)
		printf("id %d %s\n", msg->id, msg->buf);
	/*
	 * dt = (now.tv_sec - msg->ts.tv_sec) * 1000.0;
	 * dt += (now.tv_nsec - msg->ts.tv_nsec) / 1000000.0;
	 */

	/* if (dt > 5) */

	return 0;
}

static int service_func(struct xbus_request *req, void *p)
{
	printf("req %s\n", req->req);

	memcpy(req->resp, req->req, req->resp_len);
	/* sprintf(req->response, "ack %d", ack++); */

	return 0;
}

static __used int test_service(int argc, char **argv)
{
	xbus_service("req", service_func, NULL);

	return 0;
}

static __used int test_request(int argc, char **argv)
{
	struct xbus_request req;
	char req_buf[32], resp_buf[32];
	int i = 0;
	int ret;

	xbus_init("sub", 1);
	xbus_request_init("req", &req);

	while (1) {
		sprintf(req_buf, "req %d", i++);
		req.req = req_buf;
		req.req_len = sizeof(req_buf);
		req.resp = resp_buf;
		req.resp_len = sizeof(resp_buf);
		printf("req buf %s\n", req_buf);
		ret = xbus_request(&req);
		if (ret < 0) {
			sleep(1);
			continue;
		}
		printf("resp_buf %s\n", resp_buf);
		/* sleep(1); */
		usleep(20000);
	}

	return 0;
}

static void notify(struct xbus_notification *mn, void *data)
{
	switch (mn->ev) {
	case XBUS_EVENT_NODE_OFFLINE:
		printf("Node %s is offline\n", mn->name);
		if (!strncmp(mn->name, "publish-", 8)) {
			printf("exit..........\n");
			abort();
		}
		break;
	case XBUS_EVENT_NODE_ONLINE:
		printf("Node %s is online\n", mn->name);
		break;
	case XBUS_EVENT_SUB_OFFLINE:
		printf("Sub %s is offline\n", mn->name);
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

static int test_sub(int argc, char **argv)
{
	struct msg_test msg;
	struct test_data *tds;
	struct xbus_notifier ntf = {0};
	time_t t;
	char *buf;
	struct xbus_pub pub;
	int sub_cnt = 1;
	int i = 0;
	int id;
	int size;
	int ret;

	if (argc > 1)
		sub_cnt = atoi(argv[1]);

	srand((unsigned) time(&t));

	xbus_init("sub", 1);

	ntf.func = notify;
	ret = xbus_register_notifier(&ntf);
	if (ret < 0) {
		printf("register notifier error\n");
		return ret;
	}

	tds = malloc(sub_cnt * sizeof(struct test_data));
	ret = (rand() % 16) * 64 + 1;
	/* target = 60; */
	for (i = 0; i < sub_cnt; i++) {
		memset(&tds[i], 0, sizeof(struct test_data));
		tds[i].target = ret;
		sprintf(tds[i].topic, "ptopic%d", i);
		id = xbus_subscribe(tds[i].topic, 512, msg_handler, &tds[i]);
	}

	while (1)
		sleep(3600);

	xbus_pub_init(&pub, "sub0", 8);

	while (1) {
		size = rand() % 64 + 1;
		size *= 4096;
		buf = malloc(size);
		clock_gettime(CLOCK_MONOTONIC, &msg.ts);
		sprintf(msg.buf, "pub %d", i++);
		printf("send %s\n", msg.buf);
		msg.id++;
		memcpy(buf, &msg, sizeof(msg));
		xbus_publish(&pub, buf, size);
		usleep(20000);
		free(buf);
	}

	return 0;
}

static int test_shm(int argc, char **argv)
{
	struct xbus_notifier ntf = {0};
	struct test_data td;
	time_t t;
	int ret;

	srand((unsigned) time(&t));

	xbus_init("sub", 1);

	ntf.func = notify;
	ret = xbus_register_notifier(&ntf);
	if (ret < 0) {
		printf("register notifier error\n");
		return ret;
	}

	xbus_subscribe("pubshm", 512, msg_handler, &td);

	while (1)
		sleep(3600);

	return 0;
}

static int test_latency(int argc, char **argv)
{
	struct xbus_notifier ntf = {0};
	time_t t;
	int ret;

	srand((unsigned) time(&t));

	xbus_init("sub", 1);

	ntf.func = notify;
	ret = xbus_register_notifier(&ntf);
	if (ret < 0) {
		printf("register notifier error\n");
		return ret;
	}

	xbus_subscribe("pubshm", 512, shm_msg_handler, NULL);

	while (1)
		sleep(3600);

	return 0;
}

static __used int test_pub(int argc, char **argv)
{
	char buf[16] = {0};
	struct xbus_pub pub;
	int i = 0;

	xbus_pub_init(&pub, "pub0", 10);

	while (1) {
		sprintf(buf, "pub %d", i++);
		xbus_publish(&pub, buf, sizeof(buf));
	}

	return 0;
}

static int __sub_onoff_test(int argc, char **argv)
{
	struct msg_test msg;
	struct xbus_notifier ntf = {0};
	struct test_data *tds;
	char topic[32] = {0};
	uint32_t *buf;
	struct xbus_pub *pubs;
	time_t t;
	int sub_cnt = 1;
	int i = 0;
	int seq = 0;
	int id;
	int size;
	int ret;

	if (argc > 1)
		sub_cnt = atoi(argv[1]);

	xbus_init("sub", 1);

	ntf.func = notify;
	ret = xbus_register_notifier(&ntf);
	if (ret < 0) {
		printf("register notifier error\n");
		return ret;
	}

	srand((unsigned) time(&t));

	tds = malloc(sub_cnt * sizeof(struct test_data));
	ret = (rand() % 16) * 64 + 1;
	/* target = 60; */
	for (i = 0; i < sub_cnt; i++) {
		memset(&tds[i], 0, sizeof(struct test_data));
		tds[i].target = ret;
		tds[i].prev_seq = -1;
		sprintf(tds[i].topic, "ptopic%d", i);
		id = xbus_subscribe(tds[i].topic, 512, onoff_msg_handler, &tds[i]);
	}

	pubs = malloc(sub_cnt * sizeof(struct xbus_pub));
	for (i = 0; i < sub_cnt; i++) {
		sprintf(topic, "sub%d", i);
		ret = xbus_pub_init(&pubs[i], topic, 8);
		if (ret < 0) {
			printf("init publisher error %d\n", ret);
			abort();
		}
	}

	while (1) {
		size = rand() % 64 + 1;
		size *= 1024;
		/* size = 4096; */
		buf = malloc(size);
		clock_gettime(CLOCK_MONOTONIC, &msg.ts);
		sprintf(msg.buf, "pub %d", seq++);
		/* printf("send %s\n", msg.buf); */
		msg.id++;
		memcpy(buf, &msg, sizeof(msg));

		for (i = 0; i < sub_cnt; i++) {
			ret = xbus_publish(&pubs[i], buf, size);
			/* printf("ret %d\n", ret); */
		}

		free(buf);
		usleep(10000);
	}

	return 0;
}

static int run_sub_onoff_test(int argc, char **argv)
{
	pid_t pid;
	int status;
	int loop_cnt = 0;

	for (;;) {
		printf("Starting the %d tests\n", loop_cnt++);
		pid = fork();
		if (pid < 0) {
			printf("fork process error %d\n", pid);
			return pid;
		} else if (pid == 0) {
			__sub_onoff_test(argc, argv);
		}

		wait(&status);
		printf("status %d\n", status);
		if (!WIFEXITED(status)) {
			printf("sub process abnormal termination\n");
			break;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	/* test_shm(argc, argv); */
	/* test_latency(argc, argv); */
	run_sub_onoff_test(argc, argv);
	/* test_sub(argc, argv); */
	/* test_sub_sanity(argc, argv); */
	/* test_request(argc, argv); */

	return 0;
}
