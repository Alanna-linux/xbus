/**
 * xbus-tool.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Sep 22, 2021
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <getopt.h>

#include <completion.h>
#include <uapi/xbus.h>
#include <fifo.h>
#include <utils.h>
#include <../src/xbus-protocol.h>

typedef void (*log_func_t)(const char *, va_list);
extern void set_log_handler(log_func_t func);

#define MEM_INFO_STATE_END		1
struct mem_info {
	char				tag[MAX_NAME_LEN];
	uint8_t				state;
	int32_t				size;
};

struct slice_info {
	int8_t id;
	int32_t time;
	int32_t size;
};

struct slice_topic {
	char topic[MAX_NAME_LEN];
	struct xbus_pub pub;
};

#define BAG_MAGIC 	((uint32_t)(('b' << 8) | ('a' << 4) | 'g'))
struct bag_header {
	uint32_t magic;
	int8_t topic_cnt;
};

struct fifo_ele {
	struct fifo_ele *next;
	struct fifo fifo;
	unsigned int size;
};

struct cmd_struct {
	struct waker waker;
	pthread_mutex_t	mutex;

	/* topic cmd */
	struct timespec cur_ts;
	struct timespec priv_ts;
	int priv_msg_cnt;
	int msg_cnt;

	/* record cmd */
	pthread_t tid;
	FILE *fp;
	pthread_mutex_t	fifo_mutex;
	struct fifo_ele *target_fifo;
	struct fifo_ele *fifo_eles;
	unsigned int target_size;
};

struct slice_struct {
	struct cmd_struct *cmd;
	int id;
};

static int timer_set_interval(int fd, int sec, int ns)
{
	struct itimerspec new_value;
	int ret;

	new_value.it_value.tv_sec = sec;
	new_value.it_value.tv_nsec = ns;
	new_value.it_interval.tv_sec = sec;
	new_value.it_interval.tv_nsec = ns;

	ret = timerfd_settime(fd, 0, &new_value, NULL);
	if (ret < 0) {
		dprintf(1, "set time for timerfd error\n");
		return -1;
	}

	return 0;
}

void timer_wait(int fd)
{
	uint64_t exp;
	int ret;

	ret = read(fd, &exp, sizeof(uint64_t));
	if (ret != sizeof(uint64_t)) {
		printf("timer wait error\n");
		abort();
	}
}

static int cmd_init(struct cmd_struct *cmd)
{
	memset(cmd, 0x0, sizeof(struct cmd_struct));
	init_waker(&cmd->waker, NULL);
	pthread_mutex_init(&cmd->mutex, NULL);
	pthread_mutex_init(&cmd->fifo_mutex, NULL);

	return 0;
}

static void xbus_cmd_handle(int cmd, void *data, void *p)
{
	struct cmd_struct *cs = p;
	struct report_info *rinfo;

	switch (cmd) {
	case NODE_CMD_PUB_INFO:
		rinfo = data;
		printf("%s	%d\n", rinfo->topic, rinfo->count);
		break;
	case NODE_CMD_NODE_INFO:
		rinfo = data;
		printf("NODE	%s\n", rinfo->topic);
		break;
	case NODE_CMD_END:
		waker_action(&cs->waker, 1);
		break;
	default:
		break;
	}
}

static int hz_msg(void *buf, int len, void *p)
{
	struct cmd_struct *cs = p;

	pthread_mutex_lock(&cs->mutex);
	cs->msg_cnt++;
	clock_gettime(CLOCK_MONOTONIC, &cs->cur_ts);
	pthread_mutex_unlock(&cs->mutex);

	return 0;
}

static double timespec_diff(struct timespec *s, struct timespec *e)
{
	double dt;

	dt = (e->tv_sec - s->tv_sec) * 1000.0;
	dt += (e->tv_nsec - s->tv_nsec) / 1000000.0;

	return dt;
}

static double timespec_diff_us(struct timespec *s, struct timespec *e)
{
	double dt;

	dt = (e->tv_sec - s->tv_sec) * 1000000.0;
	dt += (e->tv_nsec - s->tv_nsec) / 1000.0;

	return dt;
}

static int topic_subcmd_hz(struct cmd_struct *cmd)
{
	int timerfd;
	double hz;

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

	timer_set_interval(timerfd, 1, 0);
	clock_gettime(CLOCK_MONOTONIC, &cmd->priv_ts);

	while (1) {
		timer_wait(timerfd);

		pthread_mutex_lock(&cmd->mutex);
		if (cmd->msg_cnt == cmd->priv_msg_cnt) {
			printf("No new message\n");
			pthread_mutex_unlock(&cmd->mutex);
			continue;
		}

		hz = cmd->msg_cnt - cmd->priv_msg_cnt;
		hz = hz * 1000 / timespec_diff(&cmd->priv_ts, &cmd->cur_ts);
		printf("%f\n", hz);

		cmd->priv_msg_cnt = cmd->msg_cnt;
		clock_gettime(CLOCK_MONOTONIC, &cmd->priv_ts);
		pthread_mutex_unlock(&cmd->mutex);
	}

	return 0;
}

static int topic_cmd(int argc, char **argv)
{
	struct cmd_struct cmd;

	if (argc < 1) {
		printf("cmd topic need subcmd\n");
		return -1;
	}

	cmd_init(&cmd);

	xbus_register_cmd(xbus_cmd_handle, &cmd);

	if (!strcmp(argv[0], "list")) {
		printf("TOPIC	number suscribers\n");
		xbus_send_cmd(XBUS_CMD_GET_PUB, NULL, 0);
		wait_for_action(&cmd.waker, 0);
		return 0;
	}

	if (!strcmp(argv[0], "hz")) {
		if (argc < 2) {
			printf("hz needs params\n");
			return -1;
		}

		xbus_subscribe(argv[1], 16, hz_msg, &cmd);

		return topic_subcmd_hz(&cmd);
	}

	return 0;
}

static struct fifo_ele *alloc_fifo_ele(unsigned int size)
{
	struct fifo_ele *ele;
	int ret;

	ele = malloc(sizeof(struct fifo_ele));
	if (ele == NULL) {
		printf("No memory to alloc fifo ele\n");
		abort();
	}
	memset(ele, 0, sizeof(struct fifo_ele));
	ele->size = size;

	ret = fifo_init(&ele->fifo, size);
	if (ret < 0) {
		printf("init fifo error %d\n", ret);
		abort();
	}

	return ele;
}

static void free_fifo_ele(struct fifo_ele *ele)
{
	fifo_release(&ele->fifo);
	free(ele);
}

static void cmd_add_fifo_ele(struct cmd_struct *cmd, struct fifo_ele *ele)
{
	struct fifo_ele *tail;

	pthread_mutex_lock(&cmd->fifo_mutex);
	cmd->target_size = ele->size;
	cmd->target_fifo = ele;
	if (cmd->fifo_eles == NULL) {
		cmd->fifo_eles = ele;
		pthread_mutex_unlock(&cmd->fifo_mutex);
		return;
	}

	tail = cmd->fifo_eles;
	while (tail->next)
		tail = tail->next;
	tail->next = ele;
	pthread_mutex_unlock(&cmd->fifo_mutex);
}

static int cmd_add_fifo_data(struct cmd_struct *cmd,
			void *data, unsigned int len)
{
	struct fifo_ele *ele;
	unsigned int size;
	unsigned int ret;

	size = len << 5;
	if (size > cmd->target_size) {
		ele = alloc_fifo_ele(size);
		cmd_add_fifo_ele(cmd, ele);
	}

	ele = cmd->target_fifo;
	for (;;) {
		ret = fifo_in_lock(&ele->fifo, data, len, &cmd->fifo_mutex);
		if (ret == len)
			break;

		printf("No enough space in fifo, sleeping 10ms\n");
		data += ret;
		len -= ret;
		usleep(10000);
	}

	return 0;
}

static int fifo_to_disk(struct cmd_struct *cmd, struct fifo_ele *ele)
{
	void *data;
	unsigned int len;
	int ret;

	for (;;) {
		data = fifo_prefetch_lock(&ele->fifo, &len, &cmd->fifo_mutex);
		if (data == NULL)
			break;
		ret = fwrite(data, len, 1, cmd->fp);
		if (ret < 0) {
			printf("write data to disk error %d\n", -errno);
			abort();
		}
		fifo_fetched_lock(&ele->fifo, len, &cmd->fifo_mutex);
	}

	return 0;
}

static void *record_save_thread(void *p)
{
	struct cmd_struct *cmd = p;
	struct fifo_ele *ele;

	for (;;) {
		wait_for_action(&cmd->waker, 'r');

		for (;;) {
			ele = cmd->fifo_eles;
			fifo_to_disk(cmd, ele);

			pthread_mutex_lock(&cmd->fifo_mutex);
			if (ele->next == NULL) {
				pthread_mutex_unlock(&cmd->fifo_mutex);
				break;
			}
			cmd->fifo_eles = ele->next;
			free_fifo_ele(ele);
			pthread_mutex_unlock(&cmd->fifo_mutex);
		}
	}

	return (void *)0;
}

static int record_msg(void *buf, int len, void *p)
{
	struct slice_struct *slice = p;
	struct cmd_struct *cmd = slice->cmd;
	struct slice_info sinfo;

	sinfo.id = slice->id;
	sinfo.size = len;

	pthread_mutex_lock(&cmd->mutex);
	clock_gettime(CLOCK_MONOTONIC, &cmd->cur_ts);

	if (cmd->priv_ts.tv_nsec == 0)
		sinfo.time = 0;
	else
		sinfo.time = timespec_diff_us(&cmd->priv_ts, &cmd->cur_ts);
	cmd_add_fifo_data(cmd, &sinfo, sizeof(sinfo));

	cmd_add_fifo_data(cmd, buf, len);

	/* fflush(cmd->fp); */
	cmd->priv_ts = cmd->cur_ts;
	pthread_mutex_unlock(&cmd->mutex);
	waker_action(&cmd->waker, 'r');

	return 0;
}

static int record_cmd(int argc, char **argv)
{
	struct cmd_struct cmd;
	struct option opts[] = {
		{ "output", required_argument, NULL, 'o'},
	};
	char default_file[128];
	char string[128];
	struct bag_header bag_hdr;
	struct timeval tv;
	struct tm *tm_time;
	char *output_file = NULL;
	int c;
	int i;
	int ret;

	while ((c = getopt_long(argc, argv, "o:", opts, NULL)) != EOF) {
		switch (c) {
		case 'o':
			output_file = optarg;
			break;
		default:
			break;
		}
	}

	cmd_init(&cmd);
	cmd.target_size = 1024 * 1024;
	cmd.target_fifo = alloc_fifo_ele(cmd.target_size);
	cmd_add_fifo_ele(&cmd, cmd.target_fifo);

	if (output_file == NULL) {
		gettimeofday(&tv, NULL);
		tm_time = localtime(&tv.tv_sec);
		strftime(string, sizeof string, "%Y-%m-%d-%H:%M:%S", tm_time);
		snprintf(default_file, sizeof(default_file), "bag-%s.bag", string);
		output_file = default_file;
	}

	printf("output_file %s\n", output_file);
	cmd.fp = fopen(output_file, "wb");
	if (cmd.fp == NULL) {
		printf("cannot create or open %s\n", output_file);
	}

	pthread_create(&cmd.tid, NULL, record_save_thread, &cmd);

	memset(&bag_hdr, 0, sizeof(bag_hdr));
	bag_hdr.magic = BAG_MAGIC;
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "-", 1)) {
			i++;
			continue;
		}
		bag_hdr.topic_cnt++;
	}

	printf("magic %x count %d\n", bag_hdr.magic, bag_hdr.topic_cnt);
	fwrite(&bag_hdr, sizeof(bag_hdr), 1, cmd.fp);
	printf("record topic: ");
	for (i = 0; i < argc; i++) {
		char topic[MAX_NAME_LEN] = {0};
		if (!strncmp(argv[i], "-", 1)) {
			i++;
			continue;
		}

		printf(" %s", argv[i]);
		strncpy(topic, argv[i], sizeof(topic));
		fwrite(topic, sizeof(topic), 1, cmd.fp);
	}
	printf("\n");

	c = 0;
	for (i = 0; i < argc; i++) {
		struct slice_struct *slice;
		if (!strncmp(argv[i], "-", 1)) {
			i++;
			continue;
		}

		slice = malloc(sizeof(*slice));
		if (slice == NULL) {
			printf("No memory to alloc slice struct\n");
			abort();
		}

		slice->id = c++;
		slice->cmd = &cmd;

		ret = xbus_subscribe(argv[i], 512, record_msg, slice);
		if (ret < 0) {
			printf("suscribe %s error %d ret\n", argv[i], ret);
			abort();
		}
	}

	while (1)
		sleep(3600);

	return 0;
}

static int play_cmd(int argc, char **argv)
{
	struct bag_header bag_hdr;
	struct slice_info sinfo;
	struct slice_topic *st;
	FILE *fp;
	char *buf = NULL;
	int buf_size = 0;;
	int timerfd;
	int i;
	int ret;

	if (argc != 1) {
		printf("play need only one param\n");
		return -1;
	}

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

	printf("open %s\n", argv[0]);
	fp = fopen(argv[0], "rb");
	if (fp == NULL) {
		printf("open %s error\n", argv[0]);
		return -1;
	}

	ret = fread(&bag_hdr, 1, sizeof(bag_hdr), fp);
	if (ret != sizeof(bag_hdr)) {
		printf("read bag header error\n");
		fclose(fp);
		return -1;
	}

	printf("HEADER INFO: magic 0x%x count %d\n", bag_hdr.magic, bag_hdr.topic_cnt);

	if (bag_hdr.magic != BAG_MAGIC) {
		printf("INVALID bag magic\n");
		return -1;
	}

	st = malloc(sizeof(struct slice_topic) * bag_hdr.topic_cnt);
	if (st == NULL) {
		printf("No memory to alloc slice_topic\n");
		fclose(fp);
		return -1;
	}
	memset(st, 0x0, sizeof(struct slice_topic) * bag_hdr.topic_cnt);

	for (i = 0; i < bag_hdr.topic_cnt; i++) {
		ret = fread(st[i].topic, MAX_NAME_LEN, 1, fp);
		if (ret != 1) {
			printf("read slice topic error\n");
			goto out;
		}

		printf("slice topic %d %s\n", i, st[i].topic);

		ret = xbus_pub_init(&st[i].pub, st[i].topic, 128);
		if (ret < 0) {
			printf("init pub error\n");
			goto out;
		}
	}

	for (;;) {
		int sec, ns;

		ret = fread(&sinfo, sizeof(sinfo), 1, fp);
		if (ret != 1) {
			printf("read slice info error\n");
			return -1;
		}

		/* printf("sinfo id %d size %d time %d\n", sinfo.id, sinfo.size, sinfo.time); */

		if (sinfo.id >= bag_hdr.topic_cnt) {
			printf("invalid sinfo id %d\n", sinfo.id);
			goto out;
		}

		if (buf_size < sinfo.size) {
			if (buf)
				free(buf);
			buf = malloc(sinfo.size);
			if (buf == NULL) {
				printf("No memory to alloc buf\n");
				goto out;
			}
		}

		ret = fread(buf, sinfo.size, 1, fp);
		if (ret != 1) {
			printf("read data error\n");
			goto out;
		}

		if (sinfo.time > 0) {
			sec = sinfo.time / 1000000;
			ns = sinfo.time % 1000000 * 1000;
			printf("sec %d ns %d\n", sec, ns);
			timer_set_interval(timerfd, sec, ns);
			timer_wait(timerfd);
		}

		printf("PUBLISH %s\n", st[sinfo.id].topic);
		ret = xbus_publish(&st[sinfo.id].pub, buf, sinfo.size);
		if (ret < 0)
			printf("publish %s error\n", st[sinfo.id].topic);
	}

out:
	fclose(fp);

	return 0;
}

static int mem_cmd(int argc, char **argv)
{
	struct xbus_request req;
	struct mem_info minfo;
	char service[32];
	int ret;
	int retry = 10;

	if (argc != 1) {
		printf("mem cmd need param: [node name]\n");
		return -1;
	}

	snprintf(service, sizeof(service), "srv_%s_mem", argv[0]);

	printf("service %s\n", service);
	memset(&req, 0x0, sizeof(req));
	ret = xbus_request_init(service, &req);
	if (ret < 0) {
		printf("xbus_request_init error\n");
		return -1;
	}

	req.resp = &minfo;
	req.resp_len = sizeof(minfo);
	for (;;) {
		ret = xbus_request(&req);
		if (ret < 0) {
			printf("xbus_request error\n");
			if (retry--) {
				sleep(1);
				continue;
			}
			return -1;
		}

		if (minfo.state == MEM_INFO_STATE_END)
			break;

		printf("MODULE %s: %d\n", minfo.tag, minfo.size);
	}

	return 0;
}

static int node_cmd(int argc, char **argv)
{
	struct cmd_struct cmd;

	if (argc < 1) {
		printf("cmd node need subcmd\n");
		return -1;
	}

	cmd_init(&cmd);

	xbus_register_cmd(xbus_cmd_handle, &cmd);

	if (!strcmp(argv[0], "list")) {
		printf("ONLINE NODES\n");
		xbus_send_cmd(XBUS_CMD_LIST_NODE, NULL, 0);
		wait_for_action(&cmd.waker, 1);
		return 0;
	}

	return 0;
}

static void usage(char *name)
{
	fprintf(stderr, "Usage: %s [args...]\n", name);
	fprintf(stderr, "topic list 	--- list current publish topic\n");
	fprintf(stderr, "topic hz [topic name] --- show the frequency of the topic\n");
	fprintf(stderr, "record [topics...] [-o file] --- record the topics to file\n");
	fprintf(stderr, "play [file] 	--- play the bag file\n");
	fprintf(stderr, "mem [node name] 	--- print the node memory info\n");
	fprintf(stderr, "node list 	--- list all online nodes\n");
}

static void log_func(const char *fmt, va_list arg)
{

}

int main(int argc, char **argv)
{
	int ret;

	ret = xbus_init("xbus-tool", 2);
	if (ret < 0) {
		printf("xbus_init error %d\n", ret);
		return -1;
	}

	set_log_handler(log_func);

	if (argc < 2) {
		printf("Too few arguments!\n");
		usage(argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "topic"))
		topic_cmd(argc - 2, &argv[2]);
	else if (!strcmp(argv[1], "record"))
		record_cmd(argc - 2, &argv[2]);
	else if (!strcmp(argv[1], "play"))
		play_cmd(argc - 2, &argv[2]);
	else if (!strcmp(argv[1], "mem"))
		mem_cmd(argc - 2, &argv[2]);
	else if (!strcmp(argv[1], "node"))
		node_cmd(argc - 2, &argv[2]);

	return 0;
}
