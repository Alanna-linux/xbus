/**
 * xbus-node.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#define THIS_MODULE 	"XBUS-NODE"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <generated/compile.h>
#include <log.h>
#include <idr.h>
#include <event-loop.h>
#include <os.h>
#include <hthread.h>
#include <wrapper.h>
#include <bitops.h>
#include <completion.h>
#include <notifier.h>
#include <uapi/error.h>

#include <xbus.h>
#include "sche.h"
#include "sche-trigger.h"
#include "xbus-conn.h"
#include "xbus-protocol.h"

#define PAGE_SIZE	4096
#define PAGE_SHIT	12

#define XBUS_PUB_FLAG_POOL		BIT(0)

#define NOTIFIER_MSG_TOPIC_ID		0
#define NOTIFIER_MSG_NEW_PROXY		1

#define XBUS_DEFAULT_RUNTIME_PATH	"/run/xbus2"

struct node_socket {
	union {
		struct sockaddr_un unaddr;
		struct sockaddr_in inaddr;
		struct sockaddr addr;
	};
	size_t size;
	int fd;
};

typedef int timer_func_t(void *data);
struct timer_work {
	int fd;
	int loop_id;
	timer_func_t *func;
	void *data;
};

struct connect_addr {
	char *path;
	int port;
	char *ip;
};

struct connect_work;
typedef void connect_func_t(int error, struct connect_work *work);
struct connect_work {
	struct timer_work timer;
	struct node_socket ns;
	int loop_id;
	connect_func_t *func;
	void *data;
	int retry;
	uint16_t retry_period_ms;
};

struct node_info {
	struct xbus_node	*node;
	struct idr 		is_sub_idr;
	struct idr		sub_idr;
	struct list_head	suscriber_list;
	struct list_head 	svc_list;
	int32_t			idr_id;
	char 			*name;
	int			isproxy;
	int			isremote;
	uint8_t 		ready;
};

struct wait_proxy_event {
	char 			topic[MAX_NAME_LEN];
	struct notifier_block	nb;
	int32_t			proxy_xbusid;
	int32_t			id;
	int			issvc;
	int			cmd;
};

struct proxy_node {
	struct node_info	info;
	pthread_mutex_t 	mutex;
	char			name[MAX_NAME_LEN];
	struct list_head	entry;
	struct xbus_conn	*connection;
	struct xbus_node	*node;
	struct closure_wrap 	*failed_cw;
	int			fd;
	int 			wid;
	uint8_t 		writable;
};

struct sub_info {
	struct list_head	entry;
	struct notifier_block	nb;
	char			node_name[MAX_NAME_LEN];
	char			topic[MAX_NAME_LEN];
	int			id;
	int 			issvc;
};

struct bind_node {
	struct node_info	info;
	char			name[MAX_NAME_LEN];
	pthread_mutex_t 	mutex;
	struct list_head	info_list;
	struct list_head	entry;
	struct xbus_conn	*connection;
	struct xbus_node	*node;
	struct closure_wrap 	*failed_cw;
	int			fd;
	int 			wid;
	uint8_t 		writable;
};

#define SUBSCRIBER_FLAG_LOCAL	BIT(0)
#define SUBSCRIBER_FLAG_PROXY	BIT(1)
#define SUBSCRIBER_FLAG_REMOTE	BIT(2)
#define SUBSCRIBER_FLAG_FREE	BIT(3)
struct subscriber {
	DECLARE_BITMAP(bitmap, 32);
	char			topic[MAX_NAME_LEN];
	struct list_head	head_entry;
	struct list_head	entry;
	int32_t			obj_id;
	int16_t			ni_id;
	uint8_t			head_id;
	int			flag;
	struct proxy_node	*proxy;
	struct bind_node	*bind;
	struct subscriber_head	*head;
	int32_t			closure_offset;
	enum closure_state 	closure_state;
	int			prev_seq;
};

/**
 * subcriber_head - A subscriber head
 *
 * @bitmap:	subscriber bitmap in the head
 * @remote_list: the list of remote subscriber
 * @local_list:	subscriber list that is in the same process as the publisher
 * @msg_list:	message list
 * @pool:	shared memory pool
 * @msg_cnt:	the message number in the head
 * @max_msgs_cnt: max message number in the head
 * @total:	total messages in the head current
 */
struct subscriber_head {
#define SUB_HEAD_MAX_ID		32
	DECLARE_BITMAP(bitmap, SUB_HEAD_MAX_ID);
	char			topic[MAX_NAME_LEN + 4];
	struct list_head	remote_list;
	struct list_head	msg_list;
	struct shm_pool		*pool;
	struct closure_wrap 	*failed_cw;
	int 			local_obj_id;
	int 			id;
	uint8_t 		have_local;
	int			msg_cnt;
	int			max_msgs_cnt;
	int			total;
	int 			seq;
};

struct iter_head_param {
	const char *topic;
	void *result;
};

enum obj_head_type {
	OBJ_HEAD_TYPE_NONE,
	OBJ_HEAD_TYPE_SVC,
	OBJ_HEAD_TYPE_SHM,
};

struct object_head {
#define OBJ_HEAD_MAX_ID 	32
	DECLARE_BITMAP(bitmap, OBJ_HEAD_MAX_ID);
	struct list_head	sub_list;
	struct list_head	svc_list;
	struct list_head	msg_list;
	struct list_head	node_entry;
	struct xbus_shm_pool	*pool;
	char 			*topic;
	enum obj_head_type	type;
	int32_t			id;
	uint32_t		max_msgs_cnt;
	uint32_t		msg_cnt;
	int			count;
	void			*p;
	int			seq;
};

struct sub_object {
	char			topic[MAX_NAME_LEN];
	struct list_head	node_entry;
	struct list_head	head_entry;
	int32_t 		obj_id;
	int32_t			id;
	uint8_t			head_id;
	int			queue_len;
	uint8_t 		busy;
	subscribe_func_t	*func;
	void			*data;
	int			prev_seq;
};

struct svc_object {
	char			svc_name[MAX_NAME_LEN + 4];
	struct list_head	node_entry;
	struct list_head	head_entry;
	int32_t			id;
	service_func_t		*func;
	void			*data;
};

struct closure_wrap {
	DECLARE_BITMAP(bitmap, 32);
	struct list_head	entry;
	struct list_head	head_entry;
	struct list_head	all_entry;
	struct conn_closure	*closure;
	struct xbus_conn	*conn;
	int			mark_free;
	int			seq;
	uint8_t 		failure;
};

struct wrap_group {
	struct list_head	all_list;
	struct list_head	free_list;
	pthread_mutex_t		mutex;
	int			total;
	int			free_cnt;
	int			max_free_cnt;
};

struct requester {
	char			service[MAX_NAME_LEN];
	struct xbus_node 	*node;
	struct waker		waker;
	struct node_info	*ni;
	struct conn_closure	*closure;
	int32_t			reqid;
	int32_t			srv_id;
	uint8_t 		have_local;
};

struct shm_buf {
	struct xbus_shm_buf	base;
	int			refcnt;
};

struct shm_pool {
	struct xbus_shm_pool 	base;
	pthread_mutex_t		mutex;
	struct completion	completion;
	DECLARE_BITMAP(bitmap, 32);
	int			max_cnt;
	int			buf_cnt;
	struct shm_buf		*bufs;
};

struct internal_notifier {
	struct notifier_block 	nb;
	struct internal_notifier *next;
	struct xbus_notifier 	*mntf;
};

struct xbus_node {
	char			*name;
	char			master_ip[16];
	char			*runtime_dir;
	uint8_t 		ready;
	struct list_head	svc_obj_list;
	struct list_head	obj_head_list;
	struct list_head	pub_msg_list;
	struct list_head	cmd_msg_list;
	struct wrap_group	wrap_grp;

	struct waker		waker;
	struct completion	write_completion;
	struct completion	worker_completion;
	int			received_msg_cnt;

	struct idr 		id_idr;
	struct idr		req_idr;
	struct idr		node_idr;
	struct idr		subscriber_idr;
	struct xbus_conn	*connection;
	struct xbus_conn 	*pub_conn;
	pthread_mutex_t		mutex;

	struct idr		obj_idr;
	pthread_mutex_t		obj_mutex;

	struct sche		*sche;
	pthread_t		spin_tid;

	struct blocking_notifier_head ntf_head;
	struct internal_notifier *notifiers;

	int32_t			xbusid;
	int			unix_fd;
	int			tfd;
	uint16_t		tcp_port;
	uint16_t		master_port;
	int			fd;
	int			swap_spin;

	user_cmd_func_t		*user_cmd_func;
	void			*user_func_data;
};

static struct xbus_node *xbus_node = NULL;

static inline struct xbus_node *get_xbus_node(void)
{
	return xbus_node;
}

static inline void set_xbus_node(struct xbus_node *node)
{
	xbus_node = node;
}

static inline void node_lock(struct xbus_node *node)
{
	pthread_mutex_lock(&node->mutex);
}

static inline void node_unlock(struct xbus_node *node)
{
	pthread_mutex_unlock(&node->mutex);
}

static int node_loop_add_fd(int fd, uint32_t mask,
		int (*handler)(int fd, uint32_t mask, void *p), void *data)
{
	struct xbus_node *node;

	node = get_xbus_node();

	return sche_add_fd(node->sche, fd, mask, handler, data);
}

static int node_loop_rm_id(int id)
{
	struct xbus_node *node;

	node = get_xbus_node();

	return sche_rm_id(node->sche, id);
}

static int create_tmpfile_cloexec(char *tmpname)
{
	int fd;

	fd = mkstemp(tmpname);
	if (fd >= 0) {
		fd = set_cloexec_or_close(fd);
		unlink(tmpname);
	}

	return fd;
}

static int create_anonymous_file(const char *path, off_t size)
{
	const char template[] = "/xbus-shared-XXXXXX";
	char *name;
	int fd;
	int ret;

	name = xzmalloc(strlen(path) + sizeof(template));
	if (!name)
		return -1;

	strcpy(name, path);
	strcat(name, template);

	fd = create_tmpfile_cloexec(name);

	xfree(name);

	if (fd < 0)
		return -1;

	ret = ftruncate(fd, size);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int loop_timer_handler(int fd, uint32_t mask, void *data)
{
	struct timer_work *timer = data;

	if (timer->func)
		timer->func(timer->data);

	return 0;
}

static int timer_init(struct timer_work *timer,
			timer_func_t *func, void *data)
{
	timer->fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timer->fd < 0) {
		dprintf(1, "create timerfd error\n");
		return timer->fd;
	}

	timer->func = func;
	timer->data = data;

	timer->loop_id = node_loop_add_fd(timer->fd, EVENT_READABLE,
					loop_timer_handler, timer);
	if (timer->loop_id < 0) {
		dprintf(1, "add timer fd to node loop error %d\n",
					timer->loop_id);
		close(timer->fd);
		return timer->loop_id;
	}

	return 0;
}

static inline void timer_destroy(struct timer_work *timer)
{
	node_loop_rm_id(timer->loop_id);
	close(timer->fd);
}

static int timer_update(struct timer_work *timer, int ms)
{
	struct itimerspec new_value;
	long sec, nsec;
	int ret;

	sec = ms / 1000;
	nsec = (ms % 1000) * 1000 * 1000;
	new_value.it_value.tv_sec = sec;
	new_value.it_value.tv_nsec = nsec;
	new_value.it_interval.tv_sec = sec;
	new_value.it_interval.tv_nsec = nsec;

	ret = timerfd_settime(timer->fd, 0, &new_value, NULL);
	if (ret < 0) {
		dprintf(1, "set time for timerfd error %d\n", ret);
		return ret;
	}

	return 0;
}

static void wrap_group_init(struct wrap_group *wg, int max_free_cnt)
{
	pthread_mutex_init(&wg->mutex, NULL);
	INIT_LIST_HEAD(&wg->all_list);
	INIT_LIST_HEAD(&wg->free_list);
	wg->max_free_cnt = max_free_cnt;
}

static struct closure_wrap *wrap_group_get_free(struct wrap_group *wg)
{
	struct closure_wrap *cw;

	pthread_mutex_lock(&wg->mutex);
	cw = list_first_entry_or_null(&wg->free_list, cw, entry);
	if (cw) {
		list_del(&cw->entry);
		wg->free_cnt--;
		cw->mark_free = 0;
		cw->failure = 0;
		clear_bit(32, cw->bitmap);
		goto out;
	}

	cw = xmalloc(sizeof(struct closure_wrap));
	check_ptr(cw, "No memory to alloc closure wrap\n");
	memset(cw, 0, sizeof(struct closure_wrap));

	INIT_LIST_HEAD(&cw->all_entry);
	INIT_LIST_HEAD(&cw->entry);
	INIT_LIST_HEAD(&cw->head_entry);
	list_add(&cw->all_entry, &wg->all_list);
	wg->total++;

out:
	pthread_mutex_unlock(&wg->mutex);

	return cw;
}

static void wrap_group_free(struct wrap_group *wg, struct closure_wrap *cw)
{
	pthread_mutex_lock(&wg->mutex);
	if (wg->free_cnt > wg->max_free_cnt) {
		list_del(&cw->all_entry);
		list_del(&cw->head_entry);
		list_del(&cw->entry);
		wg->total--;
		xfree(cw);
	} else {
		list_del(&cw->entry);
		list_del(&cw->head_entry);
		list_add(&cw->entry, &wg->free_list);
		cw->closure = NULL;
		cw->conn = NULL;
		wg->free_cnt++;
	}
	pthread_mutex_unlock(&wg->mutex);
}

static void node_info_lock(struct node_info *ni)
{
	struct bind_node *bn;
	struct proxy_node *pn;

	if (ni->isproxy) {
		pn = container_of(ni, pn, info);
		pthread_mutex_lock(&pn->mutex);
	} else {
		bn = container_of(ni, bn, info);
		pthread_mutex_lock(&bn->mutex);
	}

}

static void node_info_unlock(struct node_info *ni)
{
	struct bind_node *bn;
	struct proxy_node *pn;

	if (ni->isproxy) {
		pn = container_of(ni, pn, info);
		pthread_mutex_unlock(&pn->mutex);
	} else {
		bn = container_of(ni, bn, info);
		pthread_mutex_unlock(&bn->mutex);
	}

}

static int node_info_add_sub(struct node_info *ni, struct subscriber *sub)
{
	int ret;

	list_add_tail(&sub->entry, &ni->suscriber_list);
	ret = idr_alloc(&ni->sub_idr, sub, 0, 0);
	if (ret < 0) {
		dprintf(1, "Add sub %s to sub_idr error %d\n", sub->topic, ret);
		abort();
	}
	sub->ni_id = ret;

	return 0;
}

static struct subscriber *node_info_find_sub(struct node_info *ni, int32_t id)
{
	return idr_find(&ni->sub_idr, id);
}

static int iter_object_head(int id, void *p, void *data)
{
	struct iter_head_param *param = data;
	struct object_head *oh = p;
	int ret;

	ret = strcmp(oh->topic, param->topic);
	param->result = p;

	return ret == 0 ? 1 : 0;
}

static struct object_head *find_object_head_by_topic(struct xbus_node *node,
				const char *topic)
{
	struct iter_head_param param;
	int ret;

	param.topic = topic;
	ret = idr_for_each(&node->obj_idr, iter_object_head, &param);

	return ret ? param.result : NULL;
}

static struct object_head *alloc_object_head(struct xbus_node *node,
				const char *topic)
{
	struct object_head *oh;
	int ret;

	oh = xmalloc(sizeof(struct object_head));
	check_ptr(oh, "No memory to alloc object head\n");
	memset(oh, 0,sizeof(struct object_head));

	INIT_LIST_HEAD(&oh->sub_list);
	INIT_LIST_HEAD(&oh->svc_list);
	INIT_LIST_HEAD(&oh->msg_list);
	INIT_LIST_HEAD(&oh->node_entry);
	list_add_tail(&oh->node_entry, &node->obj_head_list);
	oh->p = node;
	oh->max_msgs_cnt = -1;
	oh->topic = xstrdup(topic);
	check_ptr(oh->topic, "No memory to alloc object_head topic\n");

	ret = idr_alloc(&node->obj_idr, oh, 0, 0);
	if (ret < 0) {
		dprintf(1, "idr obj alloc error\n");
		abort();
	}
	oh->id = ret;

	return oh;
}

static int head_add_svc_object(struct object_head *oh, struct svc_object *sobj)
{
	oh->max_msgs_cnt = ~(0U);

	list_add_tail(&sobj->head_entry, &oh->svc_list);

	return 0;
}

static int head_add_sub_object(struct object_head *oh, struct sub_object *sobj)
{
	if (oh->max_msgs_cnt == -1 || sobj->queue_len > oh->max_msgs_cnt)
		oh->max_msgs_cnt = sobj->queue_len;

	list_add_tail(&sobj->head_entry, &oh->sub_list);
	sobj->head_id = find_next_zero_bit(oh->bitmap, OBJ_HEAD_MAX_ID, 0);
	if (sobj->head_id == OBJ_HEAD_MAX_ID) {
		dprintf(1, "Too many sobj for id %d\n");
		return -EUSERS;
	}

	set_bit(sobj->head_id, oh->bitmap);

	return 0;
}

static int iter_node_info(int id, void *p, void *data)
{
	struct iter_head_param *param = data;
	struct node_info *ni = p;
	int ret;

	ret = strcmp(ni->name, param->topic);
	param->result = p;

	return ret == 0 ? 1 : 0;
}

static struct node_info *find_node_info_by_name(struct xbus_node *node,
				const char *name)
{
	struct iter_head_param param;
	int ret;

	node_lock(node);
	param.topic = name;
	ret = idr_for_each(&node->node_idr, iter_node_info, &param);
	node_unlock(node);

	return ret ? param.result : NULL;
}

static struct sub_info *alloc_sub_info(void)
{
	struct sub_info *si;

	si = xzmalloc(sizeof(struct sub_info));
	if (si == NULL) {
		dprintf(1, "No memory to alloc sub_info\n");
		return NULL;
	}

	INIT_LIST_HEAD(&si->entry);

	return si;
}

static void free_sub_info(struct sub_info *si)
{
	list_del(&si->entry);
	xfree(si);
}

static void __node_add_cmd_msg(struct xbus_node *node,
			struct xbus_conn *conn, struct conn_closure *closure)
{
	struct closure_wrap *cw;

	cw = wrap_group_get_free(&node->wrap_grp);
	cw->conn = conn;
	cw->closure = closure;
	list_add_tail(&cw->entry, &node->cmd_msg_list);
}

static void nonblocking_node_add_cmd_msg(struct xbus_node *node,
			struct xbus_conn *conn, struct conn_closure *closure)
{
	__node_add_cmd_msg(node, conn, closure);
	complete_all(&node->write_completion);
}

static void node_add_cmd_msg(struct xbus_node *node,
			struct xbus_conn *conn, struct conn_closure *closure)
{
	node_lock(node);
	__node_add_cmd_msg(node, conn, closure);
	node_unlock(node);
	complete_all(&node->write_completion);
}

static void node_rm_cmd_msg_by_conn(struct xbus_node *node,
			struct xbus_conn *conn)
{
	struct closure_wrap *cw, *tcw;

	list_for_each_safe(cw, tcw, &node->cmd_msg_list, entry) {
		if (cw->conn != conn)
			continue;

		conn_free_closure(cw->conn, cw->closure);
		wrap_group_free(&node->wrap_grp, cw);
	}
}

static int node_rm_topic_nonblocking(struct xbus_node *node, char *topic)
{
	blocking_notifier_call_chain(&node->ntf_head,
			XBUS_EVENT_PUB_OFFLINE, topic);

	return 0;
}

static char *get_topic_by_id(struct xbus_node *node, int id)
{
	struct object_head *oh;

	pthread_mutex_lock(&node->obj_mutex);
	oh = idr_find(&node->obj_idr, id);
	pthread_mutex_unlock(&node->obj_mutex);
	if (!oh)
		return NULL;

	return oh->topic;
}

static int iter_rqster(int id, void *p, void *data)
{
	struct iter_head_param *param = data;
	struct requester *rqster = p;
	int ret;

	ret = strcmp(rqster->service, param->topic);
	param->result = p;

	return ret == 0 ? 1 : 0;
}

static struct requester *find_rqster_by_srv(struct xbus_node *node, char *srv)
{
	struct iter_head_param param;
	int ret;

	param.topic = srv;
	ret = idr_for_each(&node->req_idr, iter_rqster, &param);

	return ret ? param.result : NULL;
}

static int iter_sub_head(int id, void *p, void *data)
{
	struct iter_head_param *param = data;
	struct subscriber_head *head = p;
	int ret;

	ret = strcmp(head->topic, param->topic);
	param->result = p;

	return ret == 0 ? 1 : 0;
}

static struct subscriber_head *find_sub_head_by_topic(struct xbus_node *node,
			const char *topic)
{
	struct iter_head_param param;
	int ret;

	param.topic = topic;
	ret = idr_for_each(&node->subscriber_idr, iter_sub_head, &param);

	return ret ? param.result : NULL;
}

/* need to guard by lock */
static struct subscriber_head *alloc_sub_head(struct xbus_node *node,
						const char *topic)
{
	struct subscriber_head *head;
	int ret;

	head = xmalloc(sizeof(struct subscriber_head));
	check_ptr(head, "alloc memroy for suscriber_head error\n");
	memset(head, 0, sizeof(struct subscriber_head));

	INIT_LIST_HEAD(&head->remote_list);
	INIT_LIST_HEAD(&head->msg_list);
	ret = idr_alloc(&node->subscriber_idr, head, 0, 0);
	if (ret < 0) {
		dprintf(1, "alloc idr %d error %d\n", ret);
		abort();
	}
	head->id = ret;
	strncpy(head->topic, topic, sizeof(head->topic));

	return head;
}

static struct subscriber *sub_head_find(struct subscriber_head *head,
					struct subscriber *sub)
{
	struct list_head *head_list;
	struct subscriber *iter_sub;
	int found = 0;

	head_list = &head->remote_list;

	list_for_each_entry(iter_sub, head_list, head_entry) {
		if (iter_sub->proxy == sub->proxy
			&& iter_sub->bind == sub->bind
			&& !(iter_sub->flag & SUBSCRIBER_FLAG_FREE)) {
			found = 1;
			break;
		}
	}

	return found ? iter_sub : NULL;
}

static struct subscriber *sub_head_new_sub(struct subscriber_head *head,
						int flag)
{
	struct subscriber *sub;

	sub = xmalloc(sizeof(struct subscriber));
	check_ptr(sub, "alloc memroy for suscriber error\n");

	memset(sub, 0, sizeof(struct subscriber));
	sub->closure_state = CLOSURE_STATE_HEADER;
	sub->head = head;
	sub->flag = flag;
	sub->head_id = find_next_zero_bit(head->bitmap, SUB_HEAD_MAX_ID, 0);
	if (sub->head_id == SUB_HEAD_MAX_ID) {
		dprintf(1, "Too many subscriber for id %d\n");
		xfree(sub);
		return NULL;
	}
	set_bit(sub->head_id, head->bitmap);
	dprintf(3, "new head id %d for sub %s\n", sub->head_id, sub->topic);

	INIT_LIST_HEAD(&sub->head_entry);
	INIT_LIST_HEAD(&sub->entry);

	head->total++;
	list_add_tail(&sub->head_entry, &head->remote_list);

	return sub;
}

static void head_destroy_sub(struct subscriber_head *head,
					struct subscriber *sub)
{
	list_del(&sub->head_entry);
	list_del(&sub->entry);
	clear_bit(sub->head_id, head->bitmap);
	dprintf(1, "bitmap 0x%x remove head id %d\n",
			head->bitmap[0], sub->head_id);
	xfree(sub);
	head->total--;
}

static struct xbus_conn *sub_get_conn(struct subscriber *sub)
{
	struct xbus_conn *conn;

	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		conn = sub->proxy->connection;
	else
		conn = sub->bind->connection;

	return conn;
}

/*
 * static int sub_send_closure(struct subscriber *sub,
 *                         struct conn_closure *closure, int block)
 * {
 *         struct xbus_conn *conn;
 *
 *         conn = sub_get_conn(sub);
 *
 *         return conn_send_closure(conn, closure, block);
 * }
 *
 */

static struct closure_wrap *sub_get_failed_cw(struct subscriber *sub)
{
	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		return sub->proxy->failed_cw;
	else
		return sub->bind->failed_cw;
}

static void sub_set_failed_cw(struct subscriber *sub, struct closure_wrap *cw)
{
	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		sub->proxy->failed_cw = cw;
	else
		sub->bind->failed_cw = cw;
}

static int sub_check_cw(struct subscriber *sub, struct closure_wrap *cw)
{
	struct closure_wrap *failed_cw;

	failed_cw = sub_get_failed_cw(sub);
	if (failed_cw == NULL)
		return 1;
	if (failed_cw && failed_cw == cw)
		return 1;

	return 0;
}

static int sub_check_writable(struct subscriber *sub)
{
	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		return READ_ONCE(sub->proxy->writable);
	else
		return READ_ONCE(sub->bind->writable);
}

static void sub_set_writable(struct subscriber *sub, uint8_t w)
{
	struct xbus_node *node;
	int id;
	int ret;

	if (sub->flag & SUBSCRIBER_FLAG_PROXY) {
		node = sub->proxy->node;
		id = sub->proxy->wid;
		WRITE_ONCE(sub->proxy->writable, w);
	} else {
		node = sub->bind->node;
		id = sub->bind->wid;
		WRITE_ONCE(sub->bind->writable, w);
	}
	ret = sche_fd_update(node->sche, id,
			EVENT_WRITABLE | EVENT_ET | EVENT_ONESHOT);
	if (ret < 0)
		dprintf(1, "set oneshot error %d\n", ret);
}

static int sub_send_pool(struct subscriber *sub,
				struct xbus_shm_pool *pool)
{
	struct xbus_node *node;
	struct conn_closure *closure;
	struct xbus_conn *conn;
	struct shm_info *sinfo;

	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		node = sub->proxy->node;
	else
		node = sub->bind->node;

	conn = sub_get_conn(sub);
	closure = conn_alloc_closure(conn, pool->id,
					sizeof(struct shm_info));
	closure->cmd = BP_CMD_NEW_SHM;
	closure->opt_id1 = sub->obj_id;
	closure->opt_id2 = sub->ni_id;
	closure->fds[0] = pool->fd;
	closure->fds_len = 1 * sizeof(int32_t);
	sinfo = closure_data(closure);
	sinfo->count = pool->count;
	sinfo->per_size = pool->per_size;

	/* ret = sub_send_closure(sub, closure, 1); */
	nonblocking_node_add_cmd_msg(node, conn, closure);
	/* conn_free_closure(node->pub_conn, closure); */

	return 0;
}

static void *pool_get_buf_addr(struct xbus_shm_pool *pool, int32_t offset)
{
	if (offset > pool->align_size * pool->count) {
		dprintf(1, "Invalid shm offset 0x%x\n", offset);
		abort();
	}

	return pool->data + offset;
}

static void pool_clear_sub(struct shm_pool *pool, struct subscriber *sub)
{
	struct shm_buf *sbuf;
	int bit;

	dbg("sub bitmap 0x%x\n", sub->bitmap[0]);
	pthread_mutex_lock(&pool->mutex);
	for_each_set_bit(bit, sub->bitmap, 32) {
		if (bit >= pool->buf_cnt) {
			dprintf(1, "Invalid shm_buf index %d\n", bit);
			continue;
		}

		sbuf = &pool->bufs[bit];
		if (sbuf->refcnt < 1)
			dprintf(1, "Wrong shm buf refcnt %d\n",
						sbuf->refcnt);
		else
			sbuf->refcnt--;

		dprintf(1, "index %d refcnt %d\n", bit, sbuf->refcnt);
		if (sbuf->refcnt == 0)
			clear_bit(bit, pool->bitmap);
	}
	pthread_mutex_unlock(&pool->mutex);
}

static void node_destroy(struct xbus_node *node)
{
	conn_destroy(node->connection);
	close(node->fd);
	release_waker(&node->waker);
	release_completion(&node->write_completion);
	release_completion(&node->worker_completion);
	xfree(node);
}

static void node_add_local_topic(struct xbus_node *node, char *topic)
{
	struct subscriber_head *head;
	struct object_head *oh;

	node_lock(node);
	oh = find_object_head_by_topic(node, topic);
	if (oh == NULL) {
		node_unlock(node);
		return;
	}

	head = find_sub_head_by_topic(node, topic);
	if (head == NULL) {
		node_unlock(node);
		return;
	}
	node_unlock(node);

	WRITE_ONCE(head->have_local, 1);
	head->local_obj_id = oh->id;

	pthread_mutex_lock(&node->obj_mutex);
	if (head->pool) {
		oh->type = OBJ_HEAD_TYPE_SHM;
		oh->pool = &head->pool->base;
	}
	pthread_mutex_unlock(&node->obj_mutex);
}

static void node_add_local_srv(struct xbus_node *node, char *service)
{
	struct object_head *oh;
	struct requester *robj;

	node_lock(node);
	oh = find_object_head_by_topic(node, service);
	if (oh == NULL) {
		node_unlock(node);
		return;
	}

	robj = find_rqster_by_srv(node, service);
	if (robj == NULL) {
		node_unlock(node);
		return;
	}

	WRITE_ONCE(robj->have_local, 1);
	robj->srv_id = oh->id;
	node_unlock(node);
}

static int node_add_subscriber(struct node_info *ni, struct subscriber *sub)
{
	struct subscriber_head *head;
	struct subscriber *new_sub;

	node_lock(ni->node);

	head = find_sub_head_by_topic(ni->node, sub->topic);
	if (head == NULL) {
		dprintf(1, "invalid subscriber %s\n", sub->topic);
		return -EINVAL;
	}

	if (head->pool && (sub->flag & SUBSCRIBER_FLAG_REMOTE)) {
		dprintf(1, "ID %s is shm topic, but the sub is remote!!\n",
				sub->obj_id);
		abort();
	}

	blocking_notifier_call_chain(&ni->node->ntf_head,
			XBUS_EVENT_SUB_ONLINE, sub->topic);

	new_sub = sub_head_find(head, sub);
	if (new_sub) {
		node_unlock(ni->node);
		return 0;
	}

	new_sub = sub_head_new_sub(head, sub->flag);
	if (new_sub == NULL) {
		dprintf(1, "Alloc new subscriber error for id%d\n", sub->obj_id);
		abort();
	}

	new_sub->obj_id = sub->obj_id;
	strcpy(new_sub->topic, sub->topic);
	if (sub->flag & SUBSCRIBER_FLAG_PROXY)
		new_sub->proxy = sub->proxy;
	else
		new_sub->bind = sub->bind;
	node_info_add_sub(ni, new_sub);

	if (head->pool)
		sub_send_pool(new_sub, &head->pool->base);

	node_unlock(ni->node);

	dprintf(3, "add suscriber id %d\n", sub->obj_id);

	return 0;
}

static int node_rm_subscriber(struct node_info *ni, struct subscriber *sub)
{
	struct subscriber_head *head;
	struct subscriber *new_sub;

	node_lock(ni->node);

	head = find_sub_head_by_topic(ni->node, sub->topic);
	if (head == NULL) {
		dprintf(1, "rm invalid subscriber %s\n", sub->topic);
		return -EINVAL;
	}

	new_sub = sub_head_find(head, sub);
	if (!new_sub) {
		printf("unable to find subscriber head for %s\n", sub->topic);
		node_unlock(ni->node);
		return -EINVAL;
	}

	blocking_notifier_call_chain(&ni->node->ntf_head,
			XBUS_EVENT_SUB_OFFLINE, new_sub->topic);

	if (new_sub->head->pool)
		pool_clear_sub(new_sub->head->pool, new_sub);
	new_sub->flag |= SUBSCRIBER_FLAG_FREE;
	list_del(&new_sub->entry);
	idr_remove(&ni->sub_idr, new_sub->obj_id);
	if (head->total)
		head->total--;
	node_unlock(ni->node);

	return 0;
}

static int ni_idr_iter_handler(int id, void *p, void *data)
{
	struct node_info *ni = p;
	char *topic;

	topic = get_topic_by_id(ni->node, id);
	if (topic)
		node_rm_topic_nonblocking(ni->node, topic);

	return 0;
}

static int req_idr_iter_handler(int id, void *p, void *data)
{
	struct node_info *ni = data;
	struct requester *rqter = p;

	if (rqter->ni == ni)
		rqter->ni = NULL;

	return 0;
}

static void unbind_srv_by_ni(struct node_info *ni)
{
	idr_for_each(&ni->node->req_idr,
			req_idr_iter_handler, ni);
}

static void node_info_release(struct node_info *ni)
{
	struct subscriber *sub, *sub1;

	node_info_lock(ni);
	idr_for_each(&ni->is_sub_idr,
			ni_idr_iter_handler, ni);
	unbind_srv_by_ni(ni);
	node_info_unlock(ni);

	list_for_each_safe(sub, sub1, &ni->suscriber_list, entry) {
		list_del(&sub->entry);
		if (sub->head->pool)
			pool_clear_sub(sub->head->pool, sub);
		dbg();
		sub->flag |= SUBSCRIBER_FLAG_FREE;

		blocking_notifier_call_chain(&ni->node->ntf_head,
				XBUS_EVENT_SUB_OFFLINE, sub->topic);
	}

	idr_destroy(&ni->is_sub_idr);
	idr_destroy(&ni->sub_idr);
}

static void proxy_destroy(struct proxy_node *proxy)
{
	struct xbus_node *node = proxy->node;

	node_lock(node);

	node_rm_cmd_msg_by_conn(node, proxy->connection);
	node_info_release(&proxy->info);
	blocking_notifier_call_chain(&node->ntf_head,
			XBUS_EVENT_NODE_OFFLINE, proxy->name);
	list_del(&proxy->entry);
	/* remove readable fd */
	sche_rm_fd(node->sche, proxy->fd);
	/* remove writable fd */
	sche_rm_fd(node->sche, proxy->fd);
	conn_put(proxy->connection);
	close(proxy->fd);
	idr_remove(&node->node_idr, proxy->info.idr_id);
	xfree(proxy);

	node_unlock(node);
}

static int proxy_node_send_cmd(struct proxy_node *proxy, int32_t id,
				int32_t xbusid, char *topic, int cmd)
{
	struct xbus_node *node = proxy->node;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	closure = conn_alloc_closure(proxy->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = cmd;
	minfo = closure_data(closure);
	minfo->xbusid = xbusid;
	minfo->id = id;
	strncpy(minfo->name, node->name, sizeof(minfo->name));
	if (topic)
		strncpy(minfo->topic, topic, sizeof(minfo->topic));

	node_add_cmd_msg(node, proxy->connection, closure);

	return 0;
}

static void release_local_shm(struct xbus_node *node,
			struct conn_closure *closure)
{
	struct subscriber_head *head;
	struct shm_pool *pool;
	struct xbus_shm_buf *shmbuf;

	node_lock(node);
	head = idr_find(&node->subscriber_idr, closure->id);
	check_ptr(head, "Unable to find sub head for id %d\n", closure->id);
	node_unlock(node);

	pool = head->pool;
	check_ptr(pool, "sub head has no shm_pool, but call it to free shm\n");

	shmbuf = closure_data(closure);
	if (shmbuf->index >= pool->max_cnt) {
		dprintf(1, "Release invalid index %d shmbuf\n", shmbuf->index);
	}

	dprintf(4, "Release local shmbuf index %d\n", shmbuf->index);
	pthread_mutex_lock(&pool->mutex);
	if (pool->bufs[shmbuf->index].refcnt < 1) {
		dprintf(1, "shmbuf refcnt %d is smaller than 1\n",
				pool->bufs[shmbuf->index].refcnt);
		abort();
	}

	pool->bufs[shmbuf->index].refcnt--;
	if (pool->bufs[shmbuf->index].refcnt == 0)
		clear_bit(shmbuf->index, pool->bitmap);

	pthread_mutex_unlock(&pool->mutex);
}

static void release_shm_cw(struct xbus_node *node, struct closure_wrap *cw)
{
	struct conn_closure *ack_closure;
	struct conn_closure *closure = cw->closure;
	struct xbus_shm_buf *shmbuf, *sbuf1;

	if (cw->conn == node->pub_conn) {
		release_local_shm(node, closure);
		return;
	}

	ack_closure = conn_alloc_closure(cw->conn, closure->id,
				sizeof(struct xbus_shm_buf));
	shmbuf = closure_data(closure);
	sbuf1 = closure_data(ack_closure);
	sbuf1->index = shmbuf->index;
	ack_closure->cmd = BP_CMD_FREE_SHM_BUF;
	node_add_cmd_msg(node, cw->conn, ack_closure);
	dprintf(4, "free shmbuf index %d\n", shmbuf->index);
}

static int process_msg_closure(struct xbus_node *node,
			struct xbus_conn *conn, struct conn_closure *closure)
{
	struct closure_wrap *cw;
	struct object_head *oh;
	int overflow = 0;

	pthread_mutex_lock(&node->obj_mutex);
	oh = idr_find(&node->obj_idr, closure->opt_id1);
	if (oh->msg_cnt >= oh->max_msgs_cnt) {
		list_for_each_entry(cw, &oh->msg_list, entry) {
			if (cw->mark_free != 0)
				continue;
			overflow = 1;
			break;
		}
		dprintf(3, "Topic %s received queue is overflow, remove the oldest\n",
				oh->topic);
	}
	pthread_mutex_unlock(&node->obj_mutex);

	if (overflow) {
		if (oh->type == OBJ_HEAD_TYPE_SHM)
			release_shm_cw(node, cw);
		pthread_mutex_lock(&node->obj_mutex);
		conn_free_closure(cw->conn, cw->closure);
		conn_put(cw->conn);
		wrap_group_free(&node->wrap_grp, cw);
		oh->msg_cnt--;
		node->received_msg_cnt--;
	} else {
		pthread_mutex_lock(&node->obj_mutex);
	}

	cw = wrap_group_get_free(&node->wrap_grp);
	cw->closure = closure;
	cw->conn = conn;
	cw->seq = oh->seq++;
	conn_get(conn);

	bitmap_copy(cw->bitmap, oh->bitmap, OBJ_HEAD_MAX_ID);
	list_add_tail(&cw->entry, &oh->msg_list);
	oh->msg_cnt++;
	node->received_msg_cnt++;
	pthread_mutex_unlock(&node->obj_mutex);

	complete_all(&node->worker_completion);

	return 0;
}

static int process_req_ack_closure(struct xbus_node *node,
			struct node_info *ni, struct conn_closure *closure)
{
	struct requester *robj;
	int32_t reqid;

	closure_read(closure, &reqid, sizeof(reqid));

	node_lock(node);
	robj = idr_find(&node->req_idr, reqid);
	check_ptr(robj, "Received invalid reqid %d\n", reqid);
	node_unlock(node);

	if (robj->ni != ni) {
		dprintf(1, "robj->ni is not same as proxy\n");
		abort();
	}

	robj->closure = closure;
	waker_action(&robj->waker, 1);

	return 0;
}

static int process_shm_closure(struct xbus_node *node,
				struct conn_closure *closure)
{
	struct object_head *oh;
	struct xbus_shm_pool *pool;
	struct shm_info *sinfo;
	int size;

	if (closure->fds_len != 4) {
		dprintf(1, "Invalid fds len %d\n", closure->fds_len);
		abort();
	}

	pthread_mutex_lock(&node->obj_mutex);
	oh = idr_find(&node->obj_idr, closure->opt_id1);
	check_ptr(oh, "Not found object head for id %d\n", closure->opt_id1);

	if (oh->pool) {
		pool = oh->pool;
		munmap(pool->data, pool->align_size * pool->count);
		close(pool->fd);
		xfree(pool);
		oh->pool = NULL;
	}

	pool = xmalloc(sizeof(struct xbus_shm_pool));
	check_ptr(pool, "No memory to alloc shm pool\n");
	memset(pool, 0, sizeof(struct xbus_shm_pool));

	sinfo = closure_data(closure);

	pool->per_size = sinfo->per_size;
	pool->align_size = ALIGN(pool->per_size, sizeof(unsigned long));
	pool->count = sinfo->count;
	pool->fd = closure->fds[0];
	size = pool->align_size * pool->count;
	pool->data = mmap(NULL, size, PROT_READ | PROT_WRITE,
					MAP_SHARED, pool->fd, 0);
	if (pool->data == MAP_FAILED) {
		dprintf(1, "mmap error\n");
		xfree(pool);
		pthread_mutex_unlock(&node->obj_mutex);
		return -1;
	}

	oh->pool = pool;
	oh->type = OBJ_HEAD_TYPE_SHM;;

	pthread_mutex_unlock(&node->obj_mutex);

	return 0;
}

static int process_free_shm_buf(struct node_info *ni,
				struct conn_closure *closure)
{
	struct xbus_node *node = ni->node;
	struct subscriber_head *head;
	struct subscriber *sub;
	struct shm_pool *pool;
	struct xbus_shm_buf *shmbuf;

	node_lock(node);
	head = idr_find(&node->subscriber_idr, closure->id);
	check_ptr(head, "Unable to find sub head for id %d\n", closure->id);

	sub = node_info_find_sub(ni, closure->opt_id2);
	check_ptr(sub, "Unable to find sub %d in node_info\n",
			closure->opt_id2);
	node_unlock(node);

	pool = head->pool;
	check_ptr(pool, "sub head has no shm_pool, but call it to free shm\n");

	shmbuf = closure_data(closure);
	if (shmbuf->index >= pool->max_cnt) {
		dprintf(1, "Release invalid index %d shmbuf\n", shmbuf->index);
	}

	dprintf(4, "Release shmbuf index %d\n", shmbuf->index);
	pthread_mutex_lock(&pool->mutex);
	if (pool->bufs[shmbuf->index].refcnt < 1) {
		dprintf(1, "shmbuf refcnt %d is smaller than 1\n",
				pool->bufs[shmbuf->index].refcnt);
		abort();
	}

	pool->bufs[shmbuf->index].refcnt--;
	if (pool->bufs[shmbuf->index].refcnt == 0)
		clear_bit(shmbuf->index, pool->bitmap);

	clear_bit(shmbuf->index, sub->bitmap);

	pthread_mutex_unlock(&pool->mutex);

	return 0;
}

static int process_new_srv(struct node_info *ni, struct xbus_info *minfo)
{
	struct requester *rqster;

	dprintf(3, "service %s id %d\n", minfo->topic, minfo->id);
	node_lock(ni->node);
	rqster = find_rqster_by_srv(ni->node, minfo->topic);
	check_ptr(rqster, "Cannot found requester %s\n", minfo->topic);

	if (rqster->ni) {
		node_unlock(ni->node);
		dprintf(1, "requester %s has bound service\n", minfo->topic);
		return -1;
	}

	rqster->ni = ni;
	rqster->srv_id = minfo->id;
	node_unlock(ni->node);

	return 0;
}

static int proxy_data(int fd, uint32_t mask, void *data)
{
	struct proxy_node *proxy = data;
	struct xbus_conn *conn = proxy->connection;
	struct subscriber sub;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	int ret;

	if (mask & (EVENT_ERROR | EVENT_HANGUP)) {
		dprintf(1, "proxy data error mask: %u\n", mask);
		proxy_destroy(proxy);
		return 0;
	}

	if (!(mask & EVENT_READABLE))
		return 0;

	ret = conn_read(conn);
	if (ret == -ENETRESET) {
		dprintf(1, "conn read error %d\n", ret);
		proxy_destroy(proxy);
		return 0;
	}

again:
	closure = conn_decode_closure(conn);
	if (closure == NULL)
		return 0;

	minfo = closure_data(closure);
	switch (closure->cmd) {
	case BP_CMD_LINK:
		strncpy(proxy->name, minfo->name, sizeof(proxy->name));
		blocking_notifier_call_chain(&proxy->node->ntf_head,
				XBUS_EVENT_NODE_ONLINE, minfo->name);
		node_lock(proxy->node);
		proxy->info.idr_id = idr_alloc(&proxy->node->node_idr,
					&proxy->info, 0, 0);
		node_unlock(proxy->node);
		notifier_call_chain(NOTIFIER_MSG_NEW_PROXY, &proxy->info);
		break;
	case BP_CMD_UNSUBCRIBE:
		memset(&sub, 0, sizeof(sub));
		sub.proxy = proxy;
		sub.flag = SUBSCRIBER_FLAG_PROXY;
		sub.obj_id = minfo->id;
		node_rm_subscriber(&proxy->info, &sub);
		break;
	case BP_CMD_SUBSCRIBE:
		memset(&sub, 0, sizeof(sub));
		sub.proxy = proxy;
		sub.flag = SUBSCRIBER_FLAG_PROXY;
		sub.obj_id = minfo->id;
		strncpy(sub.topic, minfo->topic, sizeof(sub.topic));
		if (proxy->info.isremote)
			sub.flag |= SUBSCRIBER_FLAG_REMOTE;
		node_add_subscriber(&proxy->info, &sub);
		conn_free_closure(conn, closure);
		break;
	case BP_CMD_NEW_SRV:
		process_new_srv(&proxy->info, minfo);
		break;
	case BP_CMD_MSG:
	case BP_CMD_REQUEST:
		process_msg_closure(proxy->node, conn, closure);
		break;
	case BP_CMD_REQ_ACK:
		process_req_ack_closure(proxy->node, &proxy->info, closure);
		break;
	case BP_CMD_NEW_SHM:
		process_shm_closure(proxy->node, closure);
		conn_free_closure(conn, closure);
		break;
	case BP_CMD_FREE_SHM_BUF:
		process_free_shm_buf(&proxy->info, closure);
		conn_free_closure(conn, closure);
		break;
	default:
		break;
	}

	goto again;

	return 0;
}

static int proxy_writable_event(int fd, uint32_t mask, void *data)
{
	struct proxy_node *proxy = data;

	WRITE_ONCE(proxy->writable, 1);

	return 0;
}

static struct proxy_node *proxy_create(struct xbus_node *node, int fd,
						int isremote)
{
	struct proxy_node *proxy;

	proxy = xmalloc(sizeof(struct proxy_node));
	if (proxy == NULL) {
		dprintf(1, "alloc memroy for new proxy node error\n");
		return NULL;
	}
	memset(proxy, 0x00, sizeof(struct proxy_node));

	INIT_LIST_HEAD(&proxy->entry);
	INIT_LIST_HEAD(&proxy->info.suscriber_list);
	INIT_LIST_HEAD(&proxy->info.svc_list);
	idr_init(&proxy->info.sub_idr);
	idr_init(&proxy->info.is_sub_idr);
	proxy->node = node;
	proxy->info.node = node;
	proxy->info.isproxy = 1;
	proxy->info.isremote = isremote;
	proxy->info.name = proxy->name;
	proxy->info.ready = 1;
	proxy->fd = fd;
	WRITE_ONCE(proxy->writable, 1);
	pthread_mutex_init(&proxy->mutex, NULL);

	proxy->connection = conn_create(fd, isremote);
	if (proxy->connection == NULL) {
		dprintf(1, "create xbus_conn error for proxy node\n");
		goto err_free_proxy;
	}
	conn_get(proxy->connection);

	sche_add_fd(node->sche, proxy->fd, EVENT_READABLE,
			proxy_data, proxy);
	proxy->wid = sche_add_fd(node->sche,
			proxy->fd, EVENT_WRITABLE | EVENT_ET | EVENT_ONESHOT,
			proxy_writable_event, proxy);

	return proxy;

err_free_proxy:
	close(fd);
	xfree(proxy);

	return NULL;
}

static int unix_socket_data(int fd, uint32_t mask, void *data)
{
	struct xbus_node *node = data;
	struct sockaddr_un name;
	socklen_t length;
	int client_fd;

	if ((mask & EVENT_READABLE) != 1)
		return -1;

	length = sizeof(name);
	client_fd = os_accept_cloexec(fd, (struct sockaddr *)&name, &length);
	if (client_fd < 0) {
		dprintf(1,"failed to accept\n");
	} else {
		if (!proxy_create(node, client_fd, 0))
			dprintf(1, "create proxy node error\n");
	}

	return 0;
}

static void bind_node_destroy(struct bind_node *bn)
{
	node_lock(bn->node);

	dbg();
	node_rm_cmd_msg_by_conn(bn->node, bn->connection);
	dbg();
	node_info_release(&bn->info);
	dbg();
	blocking_notifier_call_chain(&bn->node->ntf_head,
			XBUS_EVENT_NODE_OFFLINE, bn->name);

	dbg();
	list_del(&bn->entry);
	/* remove readable fd */
	sche_rm_fd(bn->node->sche, bn->fd);
	/* remove writable fd */
	sche_rm_fd(bn->node->sche, bn->fd);
	dbg();
	conn_put(bn->connection);
	close(bn->fd);
	idr_remove(&bn->node->node_idr, bn->info.idr_id);
	dbg();

	node_unlock(bn->node);
	dbg();
	xfree(bn);
	dbg();
}

static int bind_node_data(int fd, uint32_t mask, void *data)
{
	struct bind_node *bn = data;
	struct xbus_conn *conn = bn->connection;
	struct subscriber sub;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	int ret;

	if (mask & (EVENT_ERROR | EVENT_HANGUP)) {
		dprintf(1, "bind node error mask: %u\n", mask);
		bind_node_destroy(bn);
		return 0;
	}

	if (!(mask & EVENT_READABLE))
		return 0;

	ret = conn_read(conn);
	if (ret == -ENETRESET) {
		dprintf(1, "conn read error %d\n", ret);
		bind_node_destroy(bn);
		return 0;
	}

again:
	closure = conn_decode_closure(conn);
	if (closure == NULL)
		return 0;

	dprintf(4, "proxy received cmd %d id %d len %d\n",
			closure->cmd, closure->id, closure->len);
	minfo = closure_data(closure);
	switch (closure->cmd) {
	case BP_CMD_UNSUBCRIBE:
		memset(&sub, 0, sizeof(sub));
		sub.bind = bn;
		sub.obj_id = minfo->id;
		strncpy(sub.topic, minfo->topic, sizeof(sub.topic));
		if (bn->info.isremote)
			sub.flag = SUBSCRIBER_FLAG_REMOTE;
		node_rm_subscriber(&bn->info, &sub);
		break;
	case BP_CMD_SUBSCRIBE:
		memset(&sub, 0, sizeof(sub));
		sub.bind = bn;
		sub.obj_id = minfo->id;
		strncpy(sub.topic, minfo->topic, sizeof(sub.topic));
		if (bn->info.isremote)
			sub.flag = SUBSCRIBER_FLAG_REMOTE;
		node_add_subscriber(&bn->info, &sub);
		conn_free_closure(conn, closure);
		break;
	case BP_CMD_NEW_SRV:
		process_new_srv(&bn->info, minfo);
		break;
	case BP_CMD_MSG:
	case BP_CMD_REQUEST:
		process_msg_closure(bn->node, conn, closure);
		break;
	case BP_CMD_REQ_ACK:
		process_req_ack_closure(bn->node, &bn->info, closure);
		break;
	case BP_CMD_NEW_SHM:
		process_shm_closure(bn->node, closure);
		conn_free_closure(conn, closure);
		break;
	case BP_CMD_FREE_SHM_BUF:
		process_free_shm_buf(&bn->info, closure);
		conn_free_closure(conn, closure);
		break;
	default:
		break;
	}

	goto again;

	return 0;
}

static int bind_node_send_cmd(struct bind_node *bn, int32_t id,
				int32_t xbusid, char *topic, int cmd)
{
	struct xbus_node *node = bn->node;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	closure = conn_alloc_closure(bn->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = cmd;
	minfo = closure_data(closure);
	minfo->xbusid = xbusid;
	minfo->id = id;
	strncpy(minfo->name, node->name, sizeof(minfo->name));
	if (topic)
		strncpy(minfo->topic, topic, sizeof(minfo->topic));

	node_add_cmd_msg(node, bn->connection, closure);

	return 0;
}

static int nonblocking_node_info_send_cmd(struct node_info *ni, int32_t id,
				int32_t xbusid, char *topic, int cmd)
{
	struct xbus_conn *conn;
	struct bind_node *bn;
	struct proxy_node *pn;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	if (ni->isproxy)
		conn = container_of(ni, pn, info)->connection;
	else
		conn = container_of(ni, bn, info)->connection;

	closure = conn_alloc_closure(conn,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = cmd;
	minfo = closure_data(closure);
	minfo->xbusid = xbusid;
	minfo->id = id;
	strncpy(minfo->name, ni->node->name, sizeof(minfo->name));
	strncpy(minfo->topic, topic, sizeof(minfo->topic));

	nonblocking_node_add_cmd_msg(ni->node, conn, closure);

	return 0;
}

static int node_info_send_cmd(struct node_info *ni, int32_t id,
				int32_t xbusid, char *topic, int cmd)
{
	struct bind_node *bn;
	struct proxy_node *pn;

	if (ni->isproxy) {
		pn = container_of(ni, pn, info);
		proxy_node_send_cmd(pn, id, xbusid, topic, cmd);
	} else {
		bn = container_of(ni, bn, info);
		bind_node_send_cmd(bn, id, xbusid, topic, cmd);
	}

	return 0;
}

static int connect_handler(int fd, uint32_t mask, void *data)
{
	struct connect_work *work = data;

	if (mask & EVENT_ERROR) {
		dprintf(1, "connect retry %d\n", work->retry);
		if (work->retry > 0) {
			work->retry--;
			timer_update(&work->timer, 1);
			return 0;
		}

		if (work->loop_id > 0) {
			node_loop_rm_id(work->loop_id);
			work->loop_id = -1;
		}

		if (work->func)
			work->func(-1, work);

		return 0;
	}

	if (work->loop_id > 0) {
		node_loop_rm_id(work->loop_id);
		work->loop_id = -1;
	}

	timer_update(&work->timer, 0);
	if (mask & EVENT_WRITABLE) {
		if (work->func)
			work->func(0, work);
	}

	return 0;
}

static int connect_timer(void *data)
{
	struct connect_work *work = data;
	int ret;

	ret = connect(work->ns.fd, &work->ns.addr, work->ns.size);
	if (ret == 0) {
		timer_update(&work->timer, 0);
		goto connect_out;
	}

	if ((errno == EINPROGRESS && work->ns.addr.sa_family == AF_INET) ||
		((errno == EAGAIN || errno == ECONNREFUSED) &&
		 work->ns.addr.sa_family == AF_LOCAL)) {

		timer_update(&work->timer, 0);
		if (work->loop_id > 0)
			return 0;

		work->loop_id = node_loop_add_fd(work->ns.fd,
					EVENT_ERROR | EVENT_WRITABLE | EVENT_ET,
					connect_handler, work);
		return 0;
	}

	if (work->retry-- <= 0)
		timer_update(&work->timer, 0);

connect_out:
	if (work->loop_id > 0) {
		node_loop_rm_id(work->loop_id);
		work->loop_id = -1;
	}

	if (work->func)
		work->func(ret, work);

	return 0;
}

static struct connect_work *alloc_connect_work(void)
{
	struct connect_work *work;
	int ret;

	work = xzmalloc(sizeof(struct connect_work));
	if (work == NULL) {
		dprintf(1, "No memory to alloc connect_work\n");
		return NULL;
	}

	ret = timer_init(&work->timer, connect_timer, work);
	if (ret < 0) {
		dprintf(1, "init timer error %d\n", ret);
		xfree(work);
		return NULL;
	}

	return work;
}

static void destroy_connect_work(struct connect_work *work)
{
	if (work->loop_id > 0)
		node_loop_rm_id(work->loop_id);
	timer_destroy(&work->timer);
	xfree(work);
}

static int add_connect_work(struct connect_work *work)
{
	int ret;

	dprintf(3, "add connect work to %s\n", work->ns.addr.sa_data);
	ret = connect(work->ns.fd, &work->ns.addr, work->ns.size);
	if (ret == 0) {
		if (work->func)
			work->func(0, work);
		return 0;
	}

	if ((errno == EINPROGRESS && work->ns.addr.sa_family == AF_INET) ||
		(errno == EAGAIN && work->ns.addr.sa_family == AF_LOCAL)) {

		work->loop_id = node_loop_add_fd(work->ns.fd,
					EVENT_ERROR | EVENT_WRITABLE | EVENT_ET,
					connect_handler, work);
		return 0;
	}

	if (work->retry == 0 || (errno != ECONNREFUSED && errno != ENETUNREACH))
		return -errno;

	if (work->retry_period_ms == 0)
		work->retry_period_ms = 300;
	timer_update(&work->timer, work->retry_period_ms);

	return 0;
}

static int tcp_socket_data(int fd, uint32_t mask, void *data)
{
	struct xbus_node *node = data;
	struct sockaddr_in addr;
	socklen_t length;
	int client_fd;

	if ((mask & EVENT_READABLE) != 1)
		return -1;

	length = sizeof(addr);
	client_fd = os_accept_cloexec(fd, (struct sockaddr *)&addr, &length);
	if (client_fd < 0) {
		dprintf(1,"failed to accept\n");
	} else {
		if (!proxy_create(node, client_fd, 1))
			dprintf(1, "create proxy node error\n");
	}

	return 0;
}

static uint16_t bind_or_find_port(int fd, uint16_t port)
{
	struct sockaddr_in in_addr;
	uint16_t find_port;
	int ret;

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	if (port > 0) {
		in_addr.sin_family = AF_INET;
		in_addr.sin_port = htons(port);
		in_addr.sin_addr.s_addr = INADDR_ANY;

		ret = bind(fd, (struct sockaddr *)&in_addr,
						sizeof(struct sockaddr_in));
		if (ret < 0)
			return ret;
		return port;
	}

	for (find_port = 10000; find_port < 65535; find_port++) {
		in_addr.sin_family = AF_INET;
		in_addr.sin_port = htons(find_port);
		in_addr.sin_addr.s_addr = INADDR_ANY;

		ret = bind(fd, (struct sockaddr *)&in_addr,
						sizeof(struct sockaddr_in));
		if (ret == 0) {
			dprintf(1, "find available port %d\n", find_port);
			break;
		}
	}

	return ret == 0 ? find_port : -1;
}

static int create_listening_tcp_socket(struct xbus_node *node,
				uint16_t port)
{
	int ret = 0;
	int rport;

	node->tfd = os_socket_cloexec(AF_INET, SOCK_STREAM, 0);
	if (node->tfd < 0)
		return -1;

	if (setsockopt(node->tfd, SOL_SOCKET, SO_REUSEADDR, &ret,
						sizeof(ret)) < 0)
		dprintf(2, "set socket SO_REUSEADDR error\n");

	rport = bind_or_find_port(node->tfd, port);
	if (rport < 0)
		return rport;

	ret = listen(node->tfd, 128);
	if (ret < 0) {
		dprintf(1, "listen error\n");
		close(node->tfd);
		return ret;
	}

	return rport;
}

static int handle_req_tcp_port(struct xbus_node *node,
				uint16_t port)
{
	struct conn_closure *closure;
	struct xbus_info *minfo;
	uint16_t rport;

	if (node->tcp_port <= 0) {
		rport = create_listening_tcp_socket(node, port);
		if (rport < 0)
			return rport;
		node->tcp_port = rport;
	}

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = XBUS_CMD_TCP_PORT;
	minfo = closure_data(closure);
	minfo->port = rport;
	node_add_cmd_msg(node, node->connection, closure);

	sche_add_fd(node->sche, node->tfd, EVENT_READABLE,
					tcp_socket_data, node);
	dprintf(3, "Listening in port %d\n", rport);

	return 0;
}

static int connect_to_socket(struct xbus_node *node,
			struct connect_addr *addr,
			connect_func_t *func, void *data)
{
	struct connect_work *work;
	int domain = PF_LOCAL;
	int fd;
	int flags;
	int ret;

	work = alloc_connect_work();
	if (work == NULL) {
		dprintf(1, "cannot alloc connect work\n");
		return -1;
	}

	memset(&work->ns, 0, sizeof(work->ns));
	if (addr->ip) {
		work->ns.inaddr.sin_family = AF_INET;
		work->ns.inaddr.sin_port = htons(addr->port);
		work->ns.inaddr.sin_addr.s_addr = inet_addr(addr->ip);
		work->ns.size = sizeof(work->ns.inaddr);
		domain = AF_INET;
	} else {
		if (strlen(node->runtime_dir) + strlen(addr->path) + 1 >
				sizeof(work->ns.unaddr.sun_path)) {
			dprintf(1, "err path: socket path \"%s/%s\" plus terminator "
					"exceeds 108 bytes\n",
					node->runtime_dir, addr->path);
			ret = -ENAMETOOLONG;
			goto err_destroy_work;
		}
		work->ns.inaddr.sin_family = AF_LOCAL;
		work->ns.size = snprintf(work->ns.unaddr.sun_path,
					sizeof(work->ns.unaddr.sun_path),
					"%s/%s", node->runtime_dir, addr->path);
		work->ns.size += offsetof(struct sockaddr_un, sun_path);
	}

	fd = os_socket_cloexec(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		dprintf(1, "failed to create PF_LOCAL socket\n");
		ret = -errno;
		goto err_destroy_work;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		dprintf(2, "bus socket F_GETFL error\n");
		flags = 0;
	}
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	work->ns.fd = fd;
	work->retry = 8;
	work->func = func;
	work->data = data;

	ret = add_connect_work(work);
	if (ret < 0) {
		dprintf(1, "add connect work error %d\n", ret);
		goto err_close_fd;
	}

	return 0;

err_close_fd:
	close(fd);
err_destroy_work:
	destroy_connect_work(work);

	return ret;
}

static int bind_writable_event(int fd, uint32_t mask, void *data)
{
	struct bind_node *bn = data;

	WRITE_ONCE(bn->writable, 1);

	return 0;
}

static struct bind_node *alloc_bind_node(struct xbus_node *node, int isremote)
{
	struct bind_node *bn;

	bn = xzmalloc(sizeof(struct bind_node));
	check_ptr(bn, "alloc memroy for bind_node error\n");

	idr_init(&bn->info.sub_idr);
	idr_init(&bn->info.is_sub_idr);
	bn->node = node;
	bn->info.node = node;
	bn->info.isproxy = 0;
	bn->info.isremote = isremote;
	bn->info.name = bn->name;
	WRITE_ONCE(bn->writable, 1);
	INIT_LIST_HEAD(&bn->entry);
	INIT_LIST_HEAD(&bn->info.suscriber_list);
	INIT_LIST_HEAD(&bn->info.svc_list);
	INIT_LIST_HEAD(&bn->info_list);

	pthread_mutex_init(&bn->mutex, NULL);
	node_lock(node);
	bn->info.idr_id = idr_alloc(&node->node_idr, &bn->info, 0, 0);
	node_unlock(node);

	return bn;
}

static void socket_connect_event(int error, struct connect_work *work)
{
	struct bind_node *bn = work->data;
	struct xbus_node *node = bn->node;
	struct sub_info *si, *tsi;
	int cmd;

	if (error != 0)
		return;

	bn->fd = work->ns.fd;
	bn->connection = conn_create(bn->fd, bn->info.isremote);
	check_ptr(bn->connection, "create connection for bind_node error\n");
	conn_get(bn->connection);

	sche_add_fd(node->sche, bn->fd, EVENT_READABLE, bind_node_data, bn);
	bn->wid = sche_add_fd(node->sche, bn->fd,
			EVENT_WRITABLE | EVENT_ET | EVENT_ONESHOT,
			bind_writable_event, bn);

	/* send node name */
	node_info_send_cmd(&bn->info, 0, 0, 0, BP_CMD_LINK);
	list_for_each_safe(si, tsi, &bn->info_list, entry) {
		if (si->issvc)
			cmd = BP_CMD_NEW_SRV;
		else
			cmd = BP_CMD_SUBSCRIBE;

		node_info_send_cmd(&bn->info, si->id,
				node->xbusid, si->topic, cmd);
		node_info_lock(&bn->info);
		idr_alloc(&bn->info.is_sub_idr, &bn->info, si->id, si->id + 1);
		node_info_unlock(&bn->info);
		free_sub_info(si);
	}

	bn->info.ready = 1;
	blocking_notifier_call_chain(&node->ntf_head,
			XBUS_EVENT_NODE_ONLINE, bn->name);

	destroy_connect_work(work);
}

static int new_proxy_notifier(struct notifier_block *nb,
			unsigned long action, void *p)
{
	struct sub_info *si;
	struct node_info *ni;
	int cmd;

	if (action != NOTIFIER_MSG_NEW_PROXY)
		return NOTIFY_DONE;

	dbg();
	ni = p;
	si = notifier_get_private(nb);

	node_info_lock(ni);
	if (si->issvc)
		cmd = BP_CMD_NEW_SRV;
	else
		cmd = BP_CMD_SUBSCRIBE;

	idr_alloc(&ni->is_sub_idr, ni, si->id, si->id + 1);
	node_info_unlock(ni);
	node_info_send_cmd(ni, si->id, 0, si->topic, cmd);

	nonblocking_unregister_notifier(nb);

	free_sub_info(si);

	return NOTIFY_DONE;
}

static int handle_link_closure(struct xbus_node *node,
		struct conn_closure *closure)
{
	struct bind_node *bn;
	struct node_info *ni;
	struct sub_info *si;
	struct object_head *oh;
	struct connect_addr ca;
	struct xbus_info *minfo;
	int cmd;
	int ret;

	minfo = closure_data(closure);

	memset(&ca, 0, sizeof(struct connect_addr));
	node_lock(node);
	oh = find_object_head_by_topic(node, minfo->topic);
	node_unlock(node);
	check_ptr(oh, "Internal error, not found object_head for topic %s\n",
				minfo->topic);

	ni = find_node_info_by_name(node, minfo->name);
	if (ni) {
		node_info_lock(ni);
		if (idr_find(&ni->is_sub_idr, oh->id)) {
			node_info_unlock(ni);
			return 0;
		}

		if (ni->ready) {
			if (minfo->issvc)
				cmd = BP_CMD_NEW_SRV;
			else
				cmd = BP_CMD_SUBSCRIBE;

			idr_alloc(&ni->is_sub_idr, ni, oh->id, oh->id + 1);
			node_info_unlock(ni);
			node_info_send_cmd(ni, oh->id, 0, minfo->topic, cmd);
			return 0;
		}
		node_info_unlock(ni);

		if (ni->isproxy) {
			dprintf(1, "The ni is proxy!! should be bind node\n");
			abort();
		}

		si = alloc_sub_info();
		if (si == NULL) {
			dprintf(1, "No memory to alloc sub info for %s\n",
					minfo->topic);
			return -ENOMEM;
		}

		strcpy(si->node_name, minfo->name);
		strcpy(si->topic, minfo->topic);
		si->id = oh->id;
		si->issvc = minfo->issvc;
		bn = container_of(ni, bn, info);
		/*
		 * info_list only accessed in read thread, no need to be guard
		 * by a lock
		 */
		list_add_tail(&si->entry, &bn->info_list);

		return 0;
	}

	si = alloc_sub_info();
	if (si == NULL) {
		dprintf(1, "No memory to alloc sub info for %s\n",
				minfo->topic);
		return -ENOMEM;
	}

	strcpy(si->node_name, minfo->name);
	strcpy(si->topic, minfo->topic);
	si->id = oh->id;
	si->issvc = minfo->issvc;

	if (closure->cmd == NODE_CMD_NEW_EVENT) {
		si->nb.notifier_call = new_proxy_notifier;
		notifier_set_private(&si->nb, si);
		register_notifier(&si->nb);
		return 0;
	}

	dprintf(3, "connect to node %s\n", minfo->name);
	bn = alloc_bind_node(node, 0);
	strncpy(bn->name, minfo->name, sizeof(bn->name));

	/* bn = container_of(ni, bn, info); */
	list_add_tail(&si->entry, &bn->info_list);

	ca.path = minfo->name;
	if (minfo->port > 0) {
		ca.ip = minfo->buf;
		ca.port = minfo->port;
	}
	ret = connect_to_socket(node, &ca, socket_connect_event, bn);
	if (ret < 0)
		return -1;

	return 0;
}

static int handle_pub_ntf_closure(struct xbus_node *node,
				struct conn_closure *closure)
{
	struct xbus_info *minfo;

	minfo = closure_data(closure);
	blocking_notifier_call_chain(&node->ntf_head,
			XBUS_EVENT_NEW_PUB, minfo->topic);

	return 0;
}

static int connect_to_bus(struct xbus_node *node, connect_func_t *func)
{
	struct connect_work *work;
	char *name;
	int domain = PF_LOCAL;
	int flags;
	int ret;

	work = alloc_connect_work();
	if (work == NULL) {
		dprintf(1, "cannot alloc connect work\n");
		return -1;
	}

	name = getenv("XBUS2_SOCKET");
	if (name == NULL)
		name = "bus-0";

	memset(&work->ns, 0, sizeof(work->ns));
	if (node->master_port > 0) {
		work->ns.inaddr.sin_family = AF_INET;
		work->ns.inaddr.sin_port = htons(node->master_port);
		work->ns.inaddr.sin_addr.s_addr = inet_addr(node->master_ip);
		work->ns.size = sizeof(work->ns.inaddr);
		domain = AF_INET;
	} else {
		if (strlen(node->runtime_dir) + strlen(name) + 1 >
				sizeof(work->ns.unaddr.sun_path)) {
			dprintf(1, "err path: socket path \"%s/%s\" plus terminator "
					"exceeds 108 bytes\n",
					node->runtime_dir, name);
			return -ENAMETOOLONG;
		}
		work->ns.inaddr.sin_family = AF_LOCAL;
		work->ns.size = snprintf(work->ns.unaddr.sun_path,
					sizeof(work->ns.unaddr.sun_path),
					"%s/%s", node->runtime_dir, name);
		work->ns.size += offsetof(struct sockaddr_un, sun_path);
	}

	node->fd = os_socket_cloexec(domain, SOCK_STREAM, 0);
	if (node->fd < 0) {
		dprintf(1, "failed to create PF_LOCAL socket\n");
		return -1;
	}

	flags = fcntl(node->fd, F_GETFL, 0);
	if (flags < 0) {
		dprintf(2, "bus socket F_GETFL error\n");
		flags = 0;
	}
	fcntl(node->fd, F_SETFL, flags | O_NONBLOCK);

	work->ns.fd = node->fd;
	work->retry = ~0;
	work->func = func;
	work->data = node;

	ret = add_connect_work(work);
	if (ret < 0) {
		dprintf(1, "add connect work error %d\n", ret);
		destroy_connect_work(work);
	}

	return 0;
}

static int node_event_dispatch(int fd, uint32_t mask, void *data);

static void resend_ntf_info(struct xbus_node *node)
{
	struct internal_notifier **iter;
	struct conn_closure *closure = NULL;

	node_lock(node);
	iter = &node->notifiers;

	while ((*iter) != NULL) {
		closure = conn_alloc_closure(node->connection, 0, 0);
		closure->cmd = XBUS_CMD_NEW_PUB_NTF;
		__node_add_cmd_msg(node, node->connection, closure);
		iter = &((*iter)->next);
	}
	node_unlock(node);

	complete_all(&node->write_completion);
}

static int iter_send_pub_info(int id, void *p, void *data)
{
	struct xbus_node *node = data;
	struct subscriber_head *head = p;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);
	closure->cmd = XBUS_CMD_PUB_TOPIC;

	minfo = closure_data(closure);

	strncpy(minfo->topic, head->topic, sizeof(minfo->topic));
	strncpy(minfo->name, node->name, sizeof(minfo->name));

	__node_add_cmd_msg(node, node->connection, closure);

	return 0;
}

static void resend_pub_info(struct xbus_node *node)
{
	node_lock(node);
	idr_for_each(&node->subscriber_idr, iter_send_pub_info, node);
	node_unlock(node);
	complete_all(&node->write_completion);
}

static int iter_send_sub_info(int id, void *p, void *data)
{
	struct xbus_node *node = data;
	struct sub_object *sobj = p;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = XBUS_CMD_SUB_TOPIC;

	minfo = closure_data(closure);

	strncpy(minfo->name, node->name, sizeof(minfo->name));
	strncpy(minfo->topic, sobj->topic, sizeof(minfo->topic));

	__node_add_cmd_msg(node, node->connection, closure);

	return 0;
}

static void resend_sub_info(struct xbus_node *node)
{
	node_lock(node);
	idr_for_each(&node->id_idr, iter_send_sub_info, node);
	node_unlock(node);
	complete_all(&node->write_completion);
}

static int iter_send_req_info(int id, void *p, void *data)
{
	struct xbus_node *node = data;
	struct requester *rqter = p;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	closure = conn_alloc_closure(node->connection, 0,
					sizeof(struct xbus_info));
	closure->cmd = XBUS_CMD_NEW_REQ;

	minfo = closure_data(closure);
	strncpy(minfo->topic, rqter->service, sizeof(minfo->topic));
	__node_add_cmd_msg(node, node->connection, closure);

	return 0;
}

static void resend_req_info(struct xbus_node *node)
{
	node_lock(node);
	idr_for_each(&node->req_idr, iter_send_req_info, node);
	node_unlock(node);
	complete_all(&node->write_completion);
}

static void resend_srv_info(struct xbus_node *node)
{
	struct svc_object *sobj;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	node_lock(node);
	list_for_each_entry(sobj, &node->svc_obj_list, node_entry) {
		closure = conn_alloc_closure(node->connection,
				0, sizeof(struct xbus_info));
		check_ptr(closure, "alloc closure error in %s\n", __func__);

		closure->cmd = XBUS_CMD_NEW_SVC;

		minfo = closure_data(closure);

		minfo->id = sobj->id;
		strncpy(minfo->name, node->name, sizeof(minfo->name));
		strncpy(minfo->topic, sobj->svc_name, sizeof(minfo->topic));
		__node_add_cmd_msg(node, node->connection, closure);
	}
	node_unlock(node);
	complete_all(&node->write_completion);
}

static void bus_reconnect_event(int error, struct connect_work *work)
{
	struct xbus_node *node = work->data;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	int ret;

	if (error < 0) {
		dprintf(1, "unable to reconnect to bus %d\n", error);
		return;
	}

	ret = conn_change_fd(node->connection, node->fd);
	if (ret < 0) {
		dprintf(1, "change connection fd error %d\n", ret);
		abort();
	}

	sche_add_fd(node->sche, node->fd, EVENT_READABLE,
			node_event_dispatch, node);

	closure = conn_alloc_closure(node->connection, 0, sizeof(*minfo));
	minfo = closure_data(closure);
	strcpy(minfo->name, node->name);
	closure->cmd = XBUS_CMD_NODE_NAME;
	node_add_cmd_msg(node, node->connection, closure);

	resend_ntf_info(node);
	resend_pub_info(node);
	resend_sub_info(node);
	resend_req_info(node);
	resend_srv_info(node);

	WRITE_ONCE(node->ready, 1);

	destroy_connect_work(work);
}

static void node_reconnect_to_bus(struct xbus_node *node)
{
	struct closure_wrap *cw, *tcw;

	WRITE_ONCE(node->ready, 0);
	node_lock(node);
	sche_rm_fd(node->sche, node->fd);
	close(node->fd);
	list_for_each_safe(cw, tcw, &node->cmd_msg_list, entry) {
		if (cw->conn == node->connection) {
			conn_free_closure(cw->conn, cw->closure);
			wrap_group_free(&node->wrap_grp, cw);
		}
	}
	node_unlock(node);

	connect_to_bus(node, bus_reconnect_event);
}

static int node_event_dispatch(int fd, uint32_t mask, void *data)
{
	struct xbus_node *node = (struct xbus_node *)data;
	struct xbus_conn *conn = node->connection;
	struct conn_closure *closure;
	int ret;

	if (mask & (EVENT_ERROR | EVENT_HANGUP)) {
		dprintf(1, "mask: %u\n", mask);
		node_reconnect_to_bus(node);
		return 0;
	}

	if (!(mask & EVENT_READABLE))
		return 0;

	ret = conn_read(conn);
	if (ret == -ENETRESET) {
		dprintf(1, "Network is close\n");
		node_reconnect_to_bus(node);
		return 0;
	}

	for (;;) {
		closure = conn_decode_closure(conn);
		if (closure == NULL)
			break;

		dprintf(4, "node cmd %d\n", closure->cmd);
		switch (closure->cmd) {
		case NODE_CMD_TCP_LINK:
		case NODE_CMD_UNIX_LINK:
		case NODE_CMD_NEW_EVENT:
			handle_link_closure(node, closure);
			break;
		case NODE_CMD_REQ_PORT:
			handle_req_tcp_port(node, 0);
			break;
		case NODE_CMD_NEW_PUB_NTF:
			handle_pub_ntf_closure(node, closure);
			break;
		default:
			if (node->user_cmd_func)
				node->user_cmd_func(closure->cmd,
					closure_data(closure),
					node->user_func_data);
			break;
		}

		conn_free_closure(node->connection, closure);
	}

	return 0;
}

static int process_sub_msg(struct object_head *oh,
			struct closure_wrap *cw, pthread_mutex_t *lock)
{
	struct sub_object *so;
	struct conn_closure *closure = cw->closure;
	int ctn = 0;
	int found = 0;

	list_for_each_entry(so, &oh->sub_list, head_entry) {
		if (READ_ONCE(so->busy)) {
			ctn = 1;
			continue;
		}

		if (test_bit(so->head_id, cw->bitmap)) {
			cw->mark_free += 2;
			clear_bit(so->head_id, cw->bitmap);
			WRITE_ONCE(so->busy, 1);
			found = 1;
			ctn = 1;
			break;
		}
	}

	if (!found)
		return ctn;

	if (cw->seq < so->prev_seq)
		dprintf(2, "wrong sequence, current %d prev %d\n",
					cw->seq, so->prev_seq);
	so->prev_seq = cw->seq;
	pthread_mutex_unlock(lock);
	so->func(closure_data(closure), closure->len,
				so->data);
	pthread_mutex_lock(lock);
	cw->mark_free -= 2;
	WRITE_ONCE(so->busy, 0);

	if (find_next_bit(cw->bitmap, OBJ_HEAD_MAX_ID, 0) == OBJ_HEAD_MAX_ID)
		return 0;

	return ctn;
}

static int process_local_req(struct requester *robj, struct xbus_request *req)
{
	struct xbus_node *node = robj->node;
	struct object_head *oh;
	struct svc_object *sobj;

	node_lock(node);
	oh = idr_find(&node->obj_idr, robj->srv_id);
	if (oh == NULL) {
		node_unlock(node);
		dprintf(1, "Not found object head %s\n", robj->service);
		return -ENOENT;
	}

	sobj = list_first_entry_or_null(&oh->svc_list, sobj, head_entry);
	node_unlock(node);

	sobj->func(req, sobj->data);

	return 0;
}

static int process_svc_msg(struct xbus_node *node, struct object_head *oh,
			struct closure_wrap *cw, pthread_mutex_t *lock)
{
	struct conn_closure *closure;
	struct xbus_request req;
	struct conn_closure *resp_closure;
	struct svc_object *sobj;

	list_del(&cw->entry);
	sobj = list_first_entry_or_null(&oh->svc_list, sobj, head_entry);
	check_ptr(sobj, "svc_list is empty\n");

	pthread_mutex_unlock(lock);

	closure = cw->closure;
	closure_read(closure, &req.reqid, sizeof(req.reqid));
	closure_read(closure, &req.req_len, sizeof(req.req_len));
	closure_read(closure, &req.resp_len, sizeof(req.resp_len));
	closure_read(closure, &req.resp_len, sizeof(req.resp_len));
	dprintf(4, "reqid %d req_len %d response_len %d\n",
			req.reqid, req.req_len, req.resp_len);
	req.req = closure_data(closure);

	resp_closure = conn_alloc_closure(cw->conn, oh->id,
					req.resp_len + sizeof(req.reqid));
	resp_closure->cmd = BP_CMD_REQ_ACK;
	closure_write(resp_closure, &req.reqid, sizeof(req.reqid));
	req.resp = (char *)closure_data(resp_closure) + sizeof(req.reqid);

	sobj->func(&req, sobj->data);
	node_add_cmd_msg(node, cw->conn, resp_closure);

	pthread_mutex_lock(lock);

	return 0;
}

static int process_shm_msg(struct xbus_node *node, struct object_head *oh,
			struct closure_wrap *cw, pthread_mutex_t *lock)
{
	struct conn_closure *closure = cw->closure;
	struct sub_object *so;
	struct xbus_shm_buf *shmbuf;
	void *p;
	int ctn = 0;
	int found = 0;

	list_for_each_entry(so, &oh->sub_list, head_entry) {
		if (READ_ONCE(so->busy)) {
			ctn = 1;
			continue;
		}

		if (test_bit(so->head_id, cw->bitmap)) {
			cw->mark_free += 2;
			clear_bit(so->head_id, cw->bitmap);
			WRITE_ONCE(so->busy, 1);
			found = 1;
			ctn = 1;
			break;
		}
	}

	shmbuf = closure_data(closure);
	p = pool_get_buf_addr(oh->pool, shmbuf->offset);

	pthread_mutex_unlock(lock);

	if (!ctn) {
		release_shm_cw(node, cw);
		pthread_mutex_lock(lock);

		return ctn;
	}

	if (!found) {
		pthread_mutex_lock(lock);
		return ctn;
	}

	so->func(p, shmbuf->size, so->data);

	pthread_mutex_lock(lock);

	if (bitmap_empty(cw->bitmap, 32) && cw->mark_free <= 2) {
		pthread_mutex_unlock(lock);
		release_shm_cw(node, cw);
		pthread_mutex_lock(lock);
	}
	cw->mark_free -= 2;
	WRITE_ONCE(so->busy, 0);

	return cw->mark_free;
}

static void *spin_thread(void *p)
{
	struct xbus_node *node = p;

	for (;;) {
		/* dprintf(1, "%s(%d)\n", __func__, __LINE__); */
		sche_run_onece(node->sche, -1);
		if (node->swap_spin) {
			dprintf(1, "Switching spin thread to xbus_spin\n");
			waker_action(&node->waker, 1);
			break;
		}
	}

	return (void *)0;
}

static int check_pending_msg(void *p)
{
	struct xbus_node *node = p;
	struct object_head *oh;
	struct closure_wrap *cw;
	int id;
	int ret = 0;

	pthread_mutex_lock(&node->obj_mutex);
	if (!node->received_msg_cnt) {
		pthread_mutex_unlock(&node->obj_mutex);
		return 0;
	}

	list_for_each_entry(oh, &node->obj_head_list, node_entry) {
		if (oh->msg_cnt < 1)
			continue;

		cw = list_first_entry_or_null(&oh->msg_list, cw, entry);
		if (cw == NULL)
			continue;

		if (oh->type != OBJ_HEAD_TYPE_NONE) {
			ret = 1;
			break;
		}

		id = find_next_bit(cw->bitmap, OBJ_HEAD_MAX_ID, 0);
		if (id == OBJ_HEAD_MAX_ID)
			continue;
		ret = 1;
		break;
	}

	pthread_mutex_unlock(&node->obj_mutex);

	return ret;
}

static void *worker_thread(void *p)
{
	struct xbus_node *node = p;
	struct object_head *oh;
	struct closure_wrap *cw;
	int ret;

	for (;;) {
		wait_for_completion(&node->worker_completion,
				check_pending_msg, node);
		pthread_mutex_lock(&node->obj_mutex);
		list_for_each_entry(oh, &node->obj_head_list, node_entry) {
			if (oh->msg_cnt < 1)
				continue;

			cw = list_first_entry_or_null(&oh->msg_list, cw, entry);
			check_ptr(cw, "msg_list is empty!!\n");

			switch (oh->type) {
			case OBJ_HEAD_TYPE_NONE:
				ret = process_sub_msg(oh, cw, &node->obj_mutex);
				break;
			case OBJ_HEAD_TYPE_SVC:
				oh->msg_cnt--;
				ret = process_svc_msg(node,
						oh, cw, &node->obj_mutex);
				break;
			case OBJ_HEAD_TYPE_SHM:
				ret = process_shm_msg(node, oh, cw,
						&node->obj_mutex);
				break;
			default:
				break;
			}

			if (ret)
				continue;

			--node->received_msg_cnt;

			if (oh->type != OBJ_HEAD_TYPE_SVC)
				oh->msg_cnt--;
			list_del(&cw->entry);

			conn_free_closure(cw->conn, cw->closure);

			conn_put(cw->conn);
			wrap_group_free(&node->wrap_grp, cw);
		}
		pthread_mutex_unlock(&node->obj_mutex);
	}

	return (void *)0;
}

static void sub_mark_shm(struct subscriber *sub, struct conn_closure *closure)
{
	struct shm_pool *pool = sub->head->pool;
	struct xbus_shm_buf *mbuf;

	mbuf = closure_data(closure);

	dprintf(4, "send index %d\n", mbuf->index);

	pthread_mutex_lock(&pool->mutex);
	if (test_bit(mbuf->index, sub->bitmap)) {
		dprintf(1, "mark shm again\n");
		abort();
	}
	set_bit(mbuf->index, sub->bitmap);
	pool->bufs[mbuf->index].refcnt++;
	pthread_mutex_unlock(&pool->mutex);
}

static void local_mark_shm(struct subscriber_head *head,
			struct conn_closure *closure)
{
	struct shm_pool *pool = head->pool;
	struct xbus_shm_buf *mbuf;

	if (head->pool == NULL)
		return;

	mbuf = closure_data(closure);
	pthread_mutex_lock(&pool->mutex);
	pool->bufs[mbuf->index].refcnt++;
	dprintf(4, "index %d refcnt %d\n",
			mbuf->index, pool->bufs[mbuf->index].refcnt);
	pthread_mutex_unlock(&pool->mutex);
}

static inline void remote_mark_shm(struct subscriber_head *head,
			struct conn_closure *closure)
{
	struct shm_pool *pool = head->pool;
	struct xbus_shm_buf *mbuf;

	if (head->pool == NULL)
		return;

	mbuf = closure_data(closure);
	pthread_mutex_lock(&pool->mutex);
	pool->bufs[mbuf->index].refcnt++;
	dprintf(4, "index %d refcnt %d\n",
			mbuf->index, pool->bufs[mbuf->index].refcnt);
	pthread_mutex_unlock(&pool->mutex);
}

static void remote_unmark_shm(struct subscriber_head *head,
			struct conn_closure *closure)
{
	struct shm_pool *pool = head->pool;
	struct xbus_shm_buf *mbuf;

	if (head->pool == NULL)
		return;

	mbuf = closure_data(closure);
	pthread_mutex_lock(&pool->mutex);
	pool->bufs[mbuf->index].refcnt--;
	if (pool->bufs[mbuf->index].refcnt == 0)
		clear_bit(mbuf->index, pool->bitmap);
	pthread_mutex_unlock(&pool->mutex);
}

static void pool_reset_buf(struct shm_pool *pool, struct conn_closure *closure)
{
	struct xbus_shm_buf *mbuf;

	if (!pool)
		return;

	mbuf = closure_data(closure);
	pthread_mutex_lock(&pool->mutex);
	if (pool->bufs[mbuf->index].refcnt == 0)
		clear_bit(mbuf->index, pool->bitmap);
	pthread_mutex_unlock(&pool->mutex);
}

static int sub_head_send_cw(struct subscriber_head *head,
			struct closure_wrap *cw, pthread_mutex_t *mutex)
{
	struct xbus_conn *conn;
	struct subscriber *sub, *tsub;
	struct conn_closure *closure = cw->closure;
	int errors = 0;
	int ret;

	dprintf(4, "cw %d head: %d\n", cw->seq, head->total);
	if (list_empty(&head->remote_list) && head->pool) {
		pool_reset_buf(head->pool, closure);
		dbg();
		return 0;
	}

	if (!head->total) {
		if (head->failed_cw == NULL) {
			cw->mark_free = 3;
			dprintf(3, "cw %d mark free 3\n", cw->seq);
			head->failed_cw = cw;
		}
		return EAGAIN;
	} else {
		if (head->failed_cw) {
			if (head->failed_cw != cw)
				return EAGAIN;
			head->failed_cw = NULL;
		}
	}

	list_for_each_safe(sub, tsub, &head->remote_list,
				head_entry) {
		if (sub->flag & SUBSCRIBER_FLAG_FREE) {
			head_destroy_sub(head, sub);
			pool_reset_buf(head->pool, closure);
			continue;
		}

		if (!sub_check_cw(sub, cw)) {
			errors++;
			continue;
		}

		if (!test_bit(sub->head_id, cw->bitmap))
			continue;

		if (!sub_check_writable(sub)) {
			sub_set_failed_cw(sub, cw);
			errors++;
			continue;
		}

		closure->cmd = BP_CMD_MSG;
		closure->offset = sub->closure_offset;
		closure->state = sub->closure_state;
		closure->opt_id1 = sub->obj_id;
		closure->opt_id2 = sub->ni_id;
		dprintf(4, "closure offset %d state %d\n", closure->offset,
				closure->state);

		conn = sub_get_conn(sub);
		conn_get(conn);

		pthread_mutex_unlock(mutex);
		ret = conn_send_closure(conn, closure, 0);
		pthread_mutex_lock(mutex);

		conn_put(conn);

		if (sub->flag & SUBSCRIBER_FLAG_FREE) {
			head_destroy_sub(head, sub);
			pool_reset_buf(head->pool, closure);
			continue;
		}

		sub->closure_offset = closure->offset;
		sub->closure_state = closure->state;

		if (ret < 0) {
			if (ret == -EAGAIN) {
				dprintf(4, "send closure error EAGAIN\n");
				sub_set_writable(sub, 0);
			}

			cw->mark_free = 3;
			cw->failure = 1;
			dprintf(4, "err closure offset %d state %d\n",
					closure->offset, closure->state);
			dprintf(4, "send %s id %d cw %d failed\n",
					sub->topic, closure->id, cw->seq);
			/* perror("send error"); */
			sub_set_failed_cw(sub, cw);
			errors++;
		} else {
			if (head->pool)
				sub_mark_shm(sub, closure);
			if (cw->seq < sub->prev_seq)
				dprintf(2, "error sequence current %d prev %d\n",
						cw->seq, sub->prev_seq);
			sub->prev_seq = cw->seq;
			dprintf(4, "send %s id %d cw %d successfully\n",
					sub->topic, closure->id, cw->seq);
			sub_set_failed_cw(sub, NULL);
			clear_bit(sub->head_id, cw->bitmap);
		}
	}

	return errors;
}

static void sub_head_rm_failure(struct subscriber_head *head, struct
					closure_wrap *cw)
{
	struct subscriber *sub;

	list_for_each_entry(sub, &head->remote_list, head_entry) {
		if (sub->flag & SUBSCRIBER_FLAG_FREE)
			continue;
		if (sub_get_failed_cw(sub) == cw) {
			sub->closure_offset = 0;
			sub->closure_state = CLOSURE_STATE_HEADER;
			sub_set_failed_cw(sub, NULL);
		}
	}
}

static int check_sub_head_writable(int id, void *p, void *data)
{
	struct subscriber_head *head = p;
	struct closure_wrap *cw;
	struct subscriber *sub;
	int found = 0;

	if (head->msg_cnt <= 0)
		return 0;

	cw = list_first_entry_or_null(&head->msg_list, cw, head_entry);
	if (cw == NULL)
		return 0;
	if (cw->mark_free == 1)
		return 1;

	cw = list_last_entry_or_null(&head->msg_list, cw, head_entry);
	if (cw == NULL)
		return 0;
	list_for_each_entry(sub, &head->remote_list, head_entry) {
		if (sub->flag & SUBSCRIBER_FLAG_FREE)
			continue;
		if (!sub_check_writable(sub))
			continue;
		if (test_bit(sub->head_id, cw->bitmap)) {
			found = 1;
			break;
		}
	}

	return found;
}

static int check_write_msg(void *p)
{
	struct xbus_node *node = p;
	int ret;

	node_lock(node);
	if (!list_empty(&node->cmd_msg_list)) {
		node_unlock(node);
		return 1;
	}

	ret = idr_for_each(&node->subscriber_idr, check_sub_head_writable, NULL);
	node_unlock(node);

	return ret;
}

static void send_cmd_msg(struct xbus_node *node)
{
	struct closure_wrap *cw, *tcw;
	struct conn_closure *closure;
	int ret;

	node_lock(node);
	list_for_each_safe(cw, tcw, &node->cmd_msg_list, entry) {
		closure = cw->closure;
		ret = conn_send_closure(cw->conn, closure, 0);
		if (ret < 0)
			continue;
		conn_free_closure(cw->conn, closure);
		wrap_group_free(&node->wrap_grp, cw);
	}
	node_unlock(node);
}

static void send_pub_msg(struct xbus_node *node)
{
	struct subscriber_head *head;
	struct closure_wrap *cw = NULL, *tcw;
	struct conn_closure *closure;
	int ret;

	for (;;) {
		node_lock(node);
		if (cw == NULL) {
			cw = list_first_entry_or_null(&node->pub_msg_list,
						cw, entry);
			if (cw == NULL) {
				node_unlock(node);
				break;
			}
		} else {
			cw = tcw;
		}

		if (&cw->entry == &node->pub_msg_list) {
			node_unlock(node);
			break;
		}

		tcw = list_next_entry(cw, entry);

		closure = cw->closure;
		head = idr_find(&node->subscriber_idr, closure->id);

		if (cw->mark_free == 1) {
			if (cw->failure)
				sub_head_rm_failure(head, cw);
			remote_unmark_shm(head, closure);
			pool_reset_buf(head->pool, closure);
			list_del(&cw->head_entry);
			list_del(&cw->entry);
			node_unlock(node);
			conn_free_closure(cw->conn, cw->closure);
			wrap_group_free(&node->wrap_grp, cw);
			continue;
		}

		if (cw->mark_free != 3)
			cw->mark_free = 2;
		ret = sub_head_send_cw(head, cw, &node->mutex);
		if (cw->mark_free != 3)
			cw->mark_free = 0;
		if (ret) {
			node_unlock(node);
			continue;
		}

		remote_unmark_shm(head, closure);
		head->msg_cnt--;
		list_del(&cw->head_entry);
		list_del(&cw->entry);
		node_unlock(node);

		conn_free_closure(cw->conn, cw->closure);
		wrap_group_free(&node->wrap_grp, cw);
	}
}

static void *write_thread(void *p)
{
	struct xbus_node *node = p;

	for (;;) {
		wait_for_completion_timeout(&node->write_completion, 2,
				check_write_msg, node);

		send_cmd_msg(node);
		send_pub_msg(node);
		conn_flush_all();
	}

	return (void *)0;
}

static struct xbus_shm_pool *xbus_create_shm_pool(size_t size, int count)
{
	struct xbus_node *node;
	struct shm_pool *pool;
	size_t alloc_size;
	int ret;
	int i;

	node = get_xbus_node();

	alloc_size = sizeof(struct shm_pool) + count * sizeof(struct shm_buf);
	pool = xmalloc(alloc_size);
	check_ptr(pool, "No memory to alloc shm pool\n");
	memset(pool, 0, alloc_size);

	pool->buf_cnt = count;
	pool->max_cnt = 32;
	pool->base.per_size = size;
	pool->base.align_size = ALIGN(pool->base.per_size,
					sizeof(unsigned long));
	pool->base.count = count;

	alloc_size = pool->base.align_size * count;
	pool->base.fd = create_anonymous_file(node->runtime_dir, alloc_size);
	if (pool->base.fd < 0) {
		dprintf(1, "Create anonymous file error %d\n", pool->base.fd);
		xfree(pool);
		return NULL;
	}

	init_completion(&pool->completion);
	ret = pthread_mutex_init(&pool->mutex, NULL);
	if (ret < 0) {
		dprintf(1, "init mutex error %d\n", ret);
		goto err_close_fd;
	}

	pool->base.data = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, pool->base.fd, 0);
	if (pool->base.data == MAP_FAILED) {
		dprintf(1, "mmap error");
		goto err_destroy_mutex;
	}

	pool->bufs = (void *)((char *)pool + sizeof(struct shm_pool));
	for (i = 0; i < count; i++) {
		pool->bufs[i].base.index = i;
		pool->bufs[i].base.offset = i * pool->base.align_size;
		pool->bufs[i].base.size = size;
		pool->bufs[i].base.data = pool->base.data
						+ pool->bufs[i].base.offset;
	}

	return &pool->base;

err_destroy_mutex:
	pthread_mutex_destroy(&pool->mutex);
err_close_fd:
	close(pool->base.fd);
	xfree(pool);

	return NULL;
}

static struct xbus_shm_buf *xbus_pool_get_buf(struct xbus_shm_pool *mpool,
					unsigned int flag)
{
	struct shm_pool *pool;
	int index;

	pool = container_of(mpool, pool, base);

retry:
	pthread_mutex_lock(&pool->mutex);
	dbg("pool bitmap 0x%x\n", pool->bitmap[0]);
	index = find_next_zero_bit(pool->bitmap, pool->buf_cnt, 0);
	if (index == pool->buf_cnt) {
		pthread_mutex_unlock(&pool->mutex);
		if (flag & G_BLOCK) {
			wait_for_completion(&pool->completion, NULL, NULL);
			goto retry;
		} else {
			return NULL;
		}
	}

	set_bit(index, pool->bitmap);
	pthread_mutex_unlock(&pool->mutex);

	return &pool->bufs[index].base;
}

static int xbus_pub_attach_pool(struct xbus_pub *pub,
				struct xbus_shm_pool *pool)
{
	struct xbus_node *node;
	struct subscriber_head *head;
	struct object_head *oh;
	struct subscriber *sub;
	struct shm_pool *spool;

	node = get_xbus_node();

	spool = container_of(pool, spool, base);

	node_lock(node);

	head = find_sub_head_by_topic(node, pub->topic);
	if (head->pool) {
		dprintf(1, "Pub is already attach another pool!!\n");
		node_unlock(node);
		return -EEXIST;
	}

	pool->id = pub->id;
	head->pool = spool;
	oh = find_object_head_by_topic(node, pub->topic);
	node_unlock(node);

	pthread_mutex_lock(&node->obj_mutex);
	if (oh) {
		oh->type = OBJ_HEAD_TYPE_SHM;
		oh->pool = &head->pool->base;
	}
	pthread_mutex_unlock(&node->obj_mutex);

	node_lock(node);
	if (list_empty(&head->remote_list)) {
		node_unlock(node);
		return 0;
	}

	list_for_each_entry(sub, &head->remote_list, head_entry) {
		if (sub->flag & SUBSCRIBER_FLAG_REMOTE)
			continue;
		sub_send_pool(sub, pool);
	}

	pub->flag = XBUS_PUB_FLAG_POOL;
	node_unlock(node);

	return 0;
}

static int xbus_notifier_handler(struct notifier_block *nb,
				unsigned long action, void *p)
{
	struct xbus_notification notification;
	struct internal_notifier *intf = container_of(nb, intf, nb);
	struct xbus_notifier *mntf = intf->mntf;

	notification.ev = action;
	switch (action) {
	case XBUS_EVENT_NODE_OFFLINE:
	case XBUS_EVENT_NODE_ONLINE:
	case XBUS_EVENT_SUB_OFFLINE:
	case XBUS_EVENT_SUB_ONLINE:
	case XBUS_EVENT_PUB_ONLINE:
	case XBUS_EVENT_PUB_OFFLINE:
	case XBUS_EVENT_NEW_PUB:
		notification.name = p;
		break;
	default:
		return 0;
	}

	if (mntf->func)
		mntf->func(&notification, mntf->data);

	return 0;
}

static int unsubcribe_idr_iter_handler(int id, void *p, void *data)
{
	struct node_info *ni = p;
	struct sub_object *sobj = data;

	node_info_lock(ni);
	if (idr_find(&ni->is_sub_idr, sobj->id)) {
		nonblocking_node_info_send_cmd(ni, sobj->id,
			ni->node->xbusid, sobj->topic, BP_CMD_UNSUBCRIBE);
		idr_remove(&ni->is_sub_idr, sobj->id);
	}
	node_info_unlock(ni);

	return 0;
}

static struct xbus_node *node_create(const char *name)
{
	struct xbus_node *node;
	const char *runtime_dir;
	char *master_ip;
	char *p;
	const char *str = "node";
	int port = XBUS_MASTER_PORT;

	node = xzmalloc(sizeof(*node));
	if (node == NULL)
		return NULL;

	if (name)
		str = name;

	node->name = xzmalloc(strlen(str) + 16);
	check_ptr(node->name, "No memory for node name\n");
	sprintf(node->name, "%s-%d", str, getpid());
	dprintf(1, "node name %s\n", node->name);

	master_ip = getenv("XBUS2_MASTER_IP");
	if (master_ip) {
		p = strrchr(master_ip, ':');
		if (p && *(p++) != '\0') {
			port = atoi(p);
			*(p - 1) = '\0';
		}

		strncpy(node->master_ip, master_ip, sizeof(node->master_ip));
		node->master_port = port;
	}

	runtime_dir = getenv("XBUS2_RUNTIME_DIR");
	if (!runtime_dir) {
		dprintf(1, "XBUS2_RUNTIME_DIR environment is not set\n");
		runtime_dir = XBUS_DEFAULT_RUNTIME_PATH;
	}

	node->runtime_dir = xzmalloc(strlen(runtime_dir) + 16);
	check_ptr(node->runtime_dir, "No memory for runtime_dir\n");

	sprintf(node->runtime_dir, "%s/%d", runtime_dir, port);
	if (access(runtime_dir, R_OK) < 0)
		mkdir_r(runtime_dir, S_IRWXU | S_IRWXG | S_IROTH);

	BLOCKING_INIT_NOTIFIER_HEAD(&node->ntf_head);
	wrap_group_init(&node->wrap_grp, 32);
	INIT_LIST_HEAD(&node->svc_obj_list);
	INIT_LIST_HEAD(&node->obj_head_list);
	INIT_LIST_HEAD(&node->pub_msg_list);
	INIT_LIST_HEAD(&node->cmd_msg_list);
	idr_init(&node->subscriber_idr);
	idr_init(&node->node_idr);
	idr_init(&node->obj_idr);
	idr_init(&node->req_idr);
	idr_init(&node->id_idr);
	pthread_mutex_init(&node->mutex, NULL);
	pthread_mutex_init(&node->obj_mutex, NULL);
	init_waker(&node->waker, NULL);
	init_completion(&node->write_completion);
	init_completion(&node->worker_completion);

	node->sche = sche_alloc("tmp");
	check_ptr(node->sche, "Can not alloc sche\n");

	dprintf(3, "RUNTIME DIR is %s\n", node->runtime_dir);
	dprintf(1, "MASTER IP %s PORT %d\n",
			master_ip ? master_ip : "NO", port);
	return node;
}

static struct xbus_node *alloc_xbus_node(const char *name)
{
	struct xbus_node *node;
	struct sockaddr_un addr;
	socklen_t size;

	node = node_create(name);
	if (node == NULL)
		return NULL;

	bzero(&addr, sizeof(struct sockaddr_un));
	addr.sun_family = AF_LOCAL;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s",
			node->runtime_dir, node->name);
	unlink(addr.sun_path);
	node->unix_fd = os_socket_cloexec(PF_LOCAL, SOCK_STREAM, 0);
	if (node->unix_fd < 0) {
		dprintf(1, "create unix socket %s error %d",
				addr.sun_path, node->unix_fd);
		abort();
	}

	size = offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path);
	if (bind(node->unix_fd, (struct sockaddr *)&addr, size) < 0) {
		dprintf(1,"bind() failed with error\n");
		abort();
	}

	if (listen(node->unix_fd, 128) < 0) {
		dprintf(1,"listen() failed with erros\n");
		abort();
	}

	sche_add_fd(node->sche, node->unix_fd, EVENT_READABLE,
			unix_socket_data, node);

	return node;
}

static void bus_connect_event(int error, struct connect_work *work)
{
	struct xbus_node *node = work->data;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	int tcp = node->master_port > 0 ? 1 : 0;

	if (error < 0) {
		dprintf(1, "unable to connect to bus %d\n", error);
		return;
	}

	dprintf(3, "connect to bus successfully\n");

	node->connection = conn_create(node->fd, tcp);
	check_ptr(node->connection, "create node connection error\n");
	node->pub_conn = conn_create(node->fd, tcp);
	check_ptr(node->pub_conn, "create pub connection error\n");
	conn_get(node->pub_conn);

	closure = conn_alloc_closure(node->connection, 0, sizeof(*minfo));
	minfo = closure_data(closure);
	strcpy(minfo->name, node->name);
	closure->cmd = XBUS_CMD_NODE_NAME;
	node_add_cmd_msg(node, node->connection, closure);

	sche_add_fd(node->sche, node->fd, EVENT_READABLE,
			node_event_dispatch, node);

	WRITE_ONCE(node->ready, 1);
	waker_action(&node->waker, 2);
	mem_register_service(node->name, -1);

	destroy_connect_work(work);
}

XBUS_EXPORT int xbus_init(const char *name, int max_threads)
{
	struct xbus_node *node;
	pthread_t work_tid[32];
	pthread_t write_tid;
	int ret;
	int i;

	log_file_open(NULL);
	dprintf(1, "XBUS VERSION: %s\n", CONFIG_VERSION);
	dprintf(1, "\tUTS_VERSION: %s\n", UTS_VERSION);
	dprintf(1, "\tXBUS COMMIT: %s\n", XBUS_COMMIT);
	dprintf(1, "\tXBUS HOST INFO: %s@%s\n",
			XBUS_COMPILE_BY, XBUS_COMPILE_HOST);
	dprintf(1, "\tXBUS COMPILER: %s\n", XBUS_COMPILER);
	mem_init();

	notifier_head_init();

	if (get_xbus_node()) {
		dprintf(1, "xbus node is already init!!\n");
		return -EEXIST;
	}

	node = alloc_xbus_node(name);
	if (node == NULL)
		return -EAGAIN;

	set_xbus_node(node);
	connect_to_bus(node, bus_connect_event);

	if (max_threads < 1)
		max_threads = 1;

	if (max_threads > 32)
		max_threads = 32;

	for (i = 0; i < max_threads; i++) {
		ret = hthread_create(&work_tid[i], "xbus-worker",
						worker_thread, node);
		if (ret < 0) {
			dprintf(1, "Create the %d thread error %d\n", i, ret);
			goto err_release_sche;
		}
	}

	ret = hthread_create(&write_tid, "xbus-write", write_thread, node);
	if (ret < 0) {
		dprintf(1, "Create the write thread error %d\n", ret);
		goto err_release_sche;
	}

	ret = hthread_create(&node->spin_tid, "xbus-spin", spin_thread, node);
	if (ret < 0) {
		dprintf(1, "create spin_thread error %d\n", ret);
		goto err_destroy_thread;
	}

	wait_for_action(&node->waker, 2);

	return 0;

err_destroy_thread:
	pthread_cancel(write_tid);
err_release_sche:
	for (; i--;)
		pthread_cancel(work_tid[i]);
	sche_release(node->sche);
	node_destroy(node);

	return -1;
}

XBUS_EXPORT int xbus_register_notifier(struct xbus_notifier *ntf)
{
	struct xbus_node *node;
	struct internal_notifier *intf, **tail;
	struct conn_closure *closure = NULL;

	node = get_xbus_node();

	intf = xzmalloc(sizeof(struct internal_notifier));
	if (intf == NULL) {
		dprintf(1, "No memory to alloc notifier\n");
		return -ENOMEM;
	}

	intf->mntf = ntf;
	intf->nb.notifier_call = xbus_notifier_handler;
	blocking_notifier_chain_register(&node->ntf_head, &intf->nb);

	node_lock(node);
	tail = &node->notifiers;
	if ((*tail) == NULL && READ_ONCE(node->ready)) {
		closure = conn_alloc_closure(node->connection, 0, 0);
		closure->cmd = XBUS_CMD_NEW_PUB_NTF;
	}

	while ((*tail) != NULL) {
		if (ntf->priority > (*tail)->mntf->priority)
			break;
		tail = &((*tail)->next);
	}

	intf->next = *tail;
	*tail = intf;

	node_unlock(node);

	if (closure) {
		conn_send_closure(node->connection, closure, 1);
		conn_free_closure(node->connection, closure);
	}

	return 0;
}

XBUS_EXPORT void xbus_unregister_notifier(struct xbus_notifier *ntf)
{
	struct xbus_node *node;
	struct internal_notifier *intf, **iter;

	node = get_xbus_node();

	node_lock(node);
	iter = &node->notifiers;

	while ((*iter) != NULL) {
		if ((*iter)->mntf == ntf) {
			blocking_notifier_chain_unregister(&node->ntf_head,
					&(*iter)->nb);
			intf = *iter;
			(*iter) = intf->next;
			xfree(intf);
			break;
		}
		iter = &((*iter)->next);
	}

	node_unlock(node);
}

XBUS_EXPORT int xbus_pub_init(struct xbus_pub *pub,
		const char *topic, int queue_len)
{
	struct xbus_node *node;
	struct subscriber_head *head;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	node = get_xbus_node();

	if (topic == NULL || pub == NULL) {
		dprintf(1, "pub or topic is NULL\n");
		return -EINVAL;
	}

	memset(pub, 0, sizeof(struct xbus_pub));
	strncpy(pub->topic, topic, sizeof(pub->topic));
	if (queue_len > 0)
		pub->max_queue_len = queue_len;
	else
		pub->max_queue_len = 16;

	node_lock(node);

	head = find_sub_head_by_topic(node, topic);
	if (head)
		goto pub_init_out;

	head = alloc_sub_head(node, topic);
	if (READ_ONCE(node->ready) == 0)
		goto pub_init_out;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);
	closure->cmd = XBUS_CMD_PUB_TOPIC;

	minfo = closure_data(closure);

	strncpy(minfo->topic, topic, sizeof(minfo->topic));
	strncpy(minfo->name, node->name, sizeof(minfo->name));

	nonblocking_node_add_cmd_msg(node, node->connection, closure);

pub_init_out:
	node_unlock(node);
	node_add_local_topic(node, head->topic);
	pub->id = head->id;
	dprintf(3, "get id %d for topic %s\n", pub->id, topic);

	return pub->id;
}

XBUS_EXPORT int xbus_pub_create_shm(struct xbus_pub *pub, int size, int count)
{
	pub->pool = xbus_create_shm_pool(size, count);

	return xbus_pub_attach_pool(pub, pub->pool);
}

XBUS_EXPORT struct xbus_shm_buf *xbus_pub_get_shmbuf(struct xbus_pub *pub,
					uint32_t flag)
{
	return xbus_pool_get_buf(pub->pool, flag);
}

XBUS_EXPORT int xbus_subscribe(const char *topic, int queue_len,
			subscribe_func_t *func, void *data)
{
	struct xbus_node *node;
	struct object_head *oh;
	struct sub_object *sobj;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	node = get_xbus_node();

	if (func == NULL) {
		dprintf(1, "param func is NULL!!\n");
		return -EINVAL;
	}

	sobj = xmalloc(sizeof(struct sub_object));
	check_ptr(sobj, "No memory to alloc sub object\n");
	memset(sobj, 0, sizeof(struct sub_object));

	INIT_LIST_HEAD(&sobj->node_entry);
	INIT_LIST_HEAD(&sobj->head_entry);
	sobj->func = func;
	sobj->data = data;
	sobj->id = -1;
	if (queue_len > 0)
		sobj->queue_len = queue_len;
	else
		sobj->queue_len = 8;
	strncpy(sobj->topic, topic, sizeof(sobj->topic));

	node_lock(node);
	sobj->obj_id = idr_alloc(&node->id_idr, sobj, 0, 0);

	oh = find_object_head_by_topic(node, topic);
	if (oh)
		goto subscribe_out;

	oh = alloc_object_head(node, topic);
	oh->type = OBJ_HEAD_TYPE_NONE;
	if (READ_ONCE(node->ready) == 0)
		goto subscribe_out;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = XBUS_CMD_SUB_TOPIC;

	minfo = closure_data(closure);

	strncpy(minfo->name, node->name, sizeof(minfo->name));
	strncpy(minfo->topic, topic, sizeof(minfo->topic));

	nonblocking_node_add_cmd_msg(node, node->connection, closure);

subscribe_out:
	node_unlock(node);
	pthread_mutex_lock(&node->obj_mutex);
	head_add_sub_object(oh, sobj);
	pthread_mutex_unlock(&node->obj_mutex);
	node_add_local_topic(node, oh->topic);

	return sobj->obj_id;
}

XBUS_EXPORT int xbus_unsubscribe(int id)
{
	struct sub_object *sobj;
	struct xbus_node *node;
	struct object_head *oh;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	node = get_xbus_node();
	node_lock(node);
	sobj = idr_find(&node->id_idr, id);
	if (sobj == NULL) {
		node_unlock(node);
		dprintf(1, "Unable to find subscriber for id %d\n", id);
		return -EINVAL;
	}

	if (sobj->id > 0)
		idr_for_each(&node->node_idr,
				unsubcribe_idr_iter_handler, sobj);
	list_del(&sobj->node_entry);
	idr_remove(&node->id_idr, id);
	node_unlock(node);

	pthread_mutex_lock(&node->obj_mutex);
	list_del(&sobj->head_entry);
	if (sobj->id > 0) {
		oh = idr_find(&node->obj_idr, sobj->id);
		clear_bit(sobj->head_id, oh->bitmap);
	}
	pthread_mutex_unlock(&node->obj_mutex);

	if (READ_ONCE(node->ready) == 0)
		return 0;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = XBUS_CMD_UNSUB_TOPIC;

	minfo = closure_data(closure);

	strncpy(minfo->name, node->name, sizeof(minfo->name));
	strncpy(minfo->topic, sobj->topic, sizeof(minfo->topic));

	node_add_cmd_msg(node, node->connection, closure);

	xfree(sobj);

	return 0;
}

XBUS_EXPORT int xbus_service(const char *service,
			service_func_t *func, void *data)
{
	struct xbus_node *node;
	struct object_head *oh;
	struct svc_object *svc_obj;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	node = get_xbus_node();

	if (func == NULL) {
		dprintf(1, "param func is NULL!!\n");
		return -EINVAL;
	}

	node_lock(node);

	oh = find_object_head_by_topic(node, service);
	if (oh) {
		node_unlock(node);
		dprintf(2, "service %s is already registered\n", service);
		return -EEXIST;
	}

	svc_obj = xmalloc(sizeof(struct svc_object));
	check_ptr(svc_obj, "No memory to alloc svc object\n");
	memset(svc_obj, 0, sizeof(struct svc_object));

	INIT_LIST_HEAD(&svc_obj->node_entry);
	INIT_LIST_HEAD(&svc_obj->head_entry);
	svc_obj->func = func;
	svc_obj->data = data;
	svc_obj->id = -1;
	snprintf(svc_obj->svc_name, sizeof(svc_obj->svc_name),
						"%s", service);
	list_add_tail(&svc_obj->node_entry, &node->svc_obj_list);

	oh = alloc_object_head(node, service);
	oh->type = OBJ_HEAD_TYPE_SVC;
	svc_obj->id = oh->id;
	head_add_svc_object(oh, svc_obj);
	node_unlock(node);
	node_add_local_srv(node, svc_obj->svc_name);
	if (READ_ONCE(node->ready) == 0)
		return 0;

	closure = conn_alloc_closure(node->connection,
			0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = XBUS_CMD_NEW_SVC;

	minfo = closure_data(closure);

	minfo->id = oh->id;
	strncpy(minfo->name, node->name, sizeof(minfo->name));
	strncpy(minfo->topic, svc_obj->svc_name, sizeof(minfo->topic));

	node_add_cmd_msg(node, node->connection, closure);

	return 0;
}

XBUS_EXPORT int xbus_request_init(const char *service,
			struct xbus_request *req)
{
	struct xbus_node *node;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	struct requester *rqter;

	node = get_xbus_node();

	if (service == NULL || req == NULL) {
		dprintf(1, "One of the params is NULL\n");
		return -EINVAL;
	}

	rqter = xmalloc(sizeof(struct requester));
	check_ptr(rqter, "No memory to alloc requester\n");
	memset(rqter, 0, sizeof(struct requester));

	init_waker(&rqter->waker, NULL);

	snprintf(rqter->service, sizeof(rqter->service), "%s", service);

	node_lock(node);
	rqter->reqid = idr_alloc(&node->req_idr, rqter, 0, 0);
	rqter->node = node;
	req->reqid = rqter->reqid;
	node_unlock(node);
	node_add_local_srv(node, rqter->service);
	if (READ_ONCE(node->ready) == 0)
		goto req_init_out;

	closure = conn_alloc_closure(node->connection, 0,
					sizeof(struct xbus_info));
	closure->cmd = XBUS_CMD_NEW_REQ;

	minfo = closure_data(closure);
	strncpy(minfo->topic, rqter->service, sizeof(minfo->topic));

	node_add_cmd_msg(node, node->connection, closure);

req_init_out:

	return rqter->reqid;
}

XBUS_EXPORT int xbus_request(struct xbus_request *req)
{
	struct xbus_node *node;
	struct proxy_node *proxy;
	struct bind_node *bind;
	struct xbus_conn *conn;
	struct requester *robj;
	struct conn_closure *closure;
	int ret;

	node = get_xbus_node();

	node_lock(node);
	robj = idr_find(&node->req_idr, req->reqid);
	if (robj == NULL) {
		dprintf(2, "No available service found\n");
		node_unlock(node);

		return -EAGAIN;
	}

	if (READ_ONCE(robj->have_local)) {
		node_unlock(node);
		return process_local_req(robj, req);
	}

	if (robj->closure) {
		dprintf(1, "robj->closure is not NULL\n");
		abort();
	}

	if (robj->ni == NULL) {
		dprintf(3, "not found service %s\n", req->service);
		node_unlock(node);
		return -ENOENT;
	}

	if (robj->ni->isproxy)
		conn = container_of(robj->ni, proxy, info)->connection;
	else
		conn = container_of(robj->ni, bind, info)->connection;
	node_unlock(node);
	dprintf(4, "robj id %d\n", robj->srv_id);
	closure = conn_alloc_closure(conn, robj->srv_id, 16 + req->req_len);
	closure_write(closure, &robj->reqid, sizeof(int32_t));
	closure_write(closure, &req->req_len, sizeof(int32_t));
	closure_write(closure, &req->resp_len, sizeof(req->resp_len));
	/* not use, just for align */
	closure_write(closure, &req->resp_len, sizeof(req->resp_len));
	closure_write(closure, req->req, req->req_len);

	closure->cmd = BP_CMD_REQUEST;
	closure->opt_id1 = robj->srv_id;
	node_add_cmd_msg(node, conn, closure);

	ret = wait_for_action_timeout(&robj->waker, 1, 1);
	if (ret < 0) {
		return ret;
	}

	check_ptr(robj->closure, "robj->closure is NULL\n");

	closure_read(robj->closure, req->resp, req->resp_len);

	conn_free_closure(conn, robj->closure);
	robj->closure = NULL;

	return 0;
}

XBUS_EXPORT int xbus_publish(struct xbus_pub *pub,
			const void *data, size_t len)
{
	struct xbus_node *node;
	struct subscriber_head *head;
	struct conn_closure *closure;
	struct closure_wrap *cw;
	int no = 0;
	int ret = 0;

	node = get_xbus_node();

	node_lock(node);
	head = idr_find(&node->subscriber_idr, pub->id);
	check_ptr(head, "unable to find subscriber head\n");

	if (!head->total)
		no = 1;
	node_unlock(node);

	closure = conn_alloc_closure(node->pub_conn, pub->id, len);
	closure_write(closure, data, len);

	remote_mark_shm(head, closure);

	if (READ_ONCE(head->have_local)) {
		conn_closure_ref(node->pub_conn, closure);
		local_mark_shm(head, closure);
		closure->opt_id1 = head->local_obj_id;
		process_msg_closure(node, node->pub_conn, closure);
	}

	node_lock(node);
	if ((head->max_msgs_cnt == -1) ||
			(pub->max_queue_len > head->max_msgs_cnt))
		head->max_msgs_cnt = pub->max_queue_len;

	if (head->msg_cnt > head->max_msgs_cnt) {
		list_for_each_entry(cw, &head->msg_list, head_entry) {
			if (cw->mark_free == 0) {
				cw->mark_free = 1;
				head->msg_cnt--;
				ret = cw->seq;
				if (list_empty(&head->remote_list))
					break;
				dprintf(3, "topic %s msg queue is overflow!"
						"remove the oldest msg %d\n",
						pub->topic, cw->seq);
				break;
			}
		}
	}

	cw = wrap_group_get_free(&node->wrap_grp);
	cw->conn = node->pub_conn;
	cw->closure = closure;
	cw->seq = head->seq++;
	if (no)
		cw->bitmap[0] = 0xff;
	else
		bitmap_copy(cw->bitmap, head->bitmap, SUB_HEAD_MAX_ID);
	head->msg_cnt++;

	dprintf(4, "add cw seq %d\n", cw->seq);
	list_add_tail(&cw->head_entry, &head->msg_list);
	list_add_tail(&cw->entry, &node->pub_msg_list);
	node_unlock(node);

	complete_all(&node->write_completion);

	return ret;
}

XBUS_EXPORT int xbus_register_cmd(user_cmd_func_t *func, void *data)
{
	struct xbus_node *node;

	node = get_xbus_node();

	if (node->user_cmd_func) {
		dprintf(1, "User cmd is registered\n");
		return -EEXIST;
	}

	node->user_cmd_func = func;
	node->user_func_data = data;

	return 0;
}

XBUS_EXPORT int xbus_send_cmd(int cmd, void *data, int len)
{
	struct xbus_node *node;
	struct conn_closure *closure;

	node = get_xbus_node();

	closure = conn_alloc_closure(node->connection, 0, len);
	if (len)
		closure_write(closure, data, len);

	closure->cmd = cmd;

	node_add_cmd_msg(node, node->connection, closure);

	return 0;
}

/*
 * attention: calling this func, it will block here util message comes.
 */
XBUS_EXPORT void xbus_spin(void)
{
	struct xbus_node *node;

	node = get_xbus_node();

	for (;;) {
		node->swap_spin = 1;
		wait_for_action(&node->waker, 1);
		break;
	}

	dprintf(1, "Switched to xbus_spin\n");
	for (;;)
		sche_run_onece(node->sche, -1);
}
