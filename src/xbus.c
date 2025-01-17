/**
 * xbus.h
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#define THIS_MODULE 	"XBUS"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <assert.h>

#include <generated/compile.h>
#include <wrapper.h>
#include <log.h>
#include <event-loop.h>
#include <os.h>
#include <bitops.h>
#include <notifier.h>
#include <uapi/error.h>
#include <xbus.h>
#include <hthread.h>
#include <completion.h>

#include "sche.h"
#include "xbus-protocol.h"
#include "xbus-conn.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX			108
#endif

#define LOCK_SUFFIXLEN			5
#define LOCK_SUFFIX			".lock"

#define NOTIFIER_PORT_READY		1

struct closure_wrap {
	struct list_head	entry;
	struct conn_closure	*closure;
	struct xbus_conn	*conn;
	int			seq;
};

struct xbus_socket {
	int				fd;
	int				fd_lock;
	struct sockaddr_un		addr;
	char				lock_addr[UNIX_PATH_MAX + LOCK_SUFFIXLEN];
	struct event_source		*source;
	int				tfd;
	int				port;
	struct event_source		*tcp_source;
	int				ufd;
	struct event_source		*udp_source;
	char				*name;
};

struct client_container {
	struct list_head		entry;
	struct list_head		client_entry;
	struct xbus_client		*client;
	struct client_head		*head;
};

struct client_head {
	char 				topic[MAX_NAME_LEN];
	struct xbus 			*bus;
	struct list_head		entry;
	struct list_head		list;
	struct vref 			ref;
	int32_t				id;
	int				ispub;
	int				count;
	int				total;
};

struct network_domain {
	char				ip[32];
	struct list_head		entry;
};

enum tcp_port_status {
	TCP_PORT_INVALID,
	TCP_PORT_REQUESTING,
	TCP_PORT_READY,
};

struct client_event {
	char 				topic[MAX_NAME_LEN];
	struct notifier_block		nb;
	struct xbus_client		*sub;
	struct xbus_client		*pub;
	int32_t				id;
	int				issvc;
};

struct xbus_client {
	char 				name[MAX_NAME_LEN];
	struct idr			linked_idr;
	enum tcp_port_status		tcp_port_status;
	int				isnamed;
	struct list_head		xbus_entry;
	struct list_head		container_list;
	int				xbusid;
	int				fd;
	int				err;
	uint8_t 			pub_ntf;
	struct xbus			*bus;
	struct network_domain		*domain;
	uint16_t			listening_port;
	struct xbus_conn		*connection;
	struct event_source		*source;
};

struct xbus {
	struct list_head		sub_list;
	struct list_head		pub_list;
	struct list_head		svc_list;
	struct list_head		req_list;
	struct list_head		domain_list;
	struct list_head		msg_list;
	struct completion 		write_completion;
	pthread_mutex_t 		mutex;
	pthread_t 			tid;
	struct network_domain		*domain;
	struct event_loop		*loop;
	struct idr			topic_id_idr;
	struct idr			xbusid_idr;
	struct list_head		client_list;
	int				run;
	int				test;
};

static struct xbus *xbus = NULL;

static struct xbus *get_xbus()
{
	return xbus;
}

static int xbus_add_msg(struct xbus *bus,
		struct xbus_conn *conn, struct conn_closure *closure)
{
	struct closure_wrap *cw;

	cw = xmalloc(sizeof(struct closure_wrap));
	if (cw == NULL) {
		dprintf(1, "No memory to alloc closure wrap\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&cw->entry);
	cw->closure = closure;
	cw->conn = conn;
	pthread_mutex_lock(&bus->mutex);
	list_add_tail(&cw->entry, &bus->msg_list);
	pthread_mutex_unlock(&bus->mutex);
	complete_all(&bus->write_completion);

	return 0;
}

static struct xbus_socket *xbus_socket_alloc(void)
{
	struct xbus_socket *s;
	char *master_ip;
	char *p;
	int port = XBUS_MASTER_PORT;

	master_ip = getenv("XBUS2_MASTER_IP");
	if (master_ip) {
		p = strrchr(master_ip, ':');
		if (p && *(p++) != '\0') {
			port = atoi(p);
			*(p - 1) = '\0';
		}
	}

	s = xmalloc(sizeof(*s));
	if (s == NULL) {
		dprintf(1,"failed to malloc socket.\n");
		return NULL;
	}

	memset(s, 0, sizeof(*s));

	s->fd = -1;
	s->fd_lock = -1;
	s->port = port;

	return s;
}

static int xbus_socket_set_name(struct xbus_socket *s, const char *socket_name)
{
	int name_size;
	char default_runtime[128] = {"/run/xbus2"};
	char port[32] = {0};
	const char *runtime_dir;

	runtime_dir = getenv("XBUS2_RUNTIME_DIR");
	if (!runtime_dir) {
		dprintf(1,"XBUS2_RUNTIME_DIR not set in environment\n");
	} else {
		memset(default_runtime, 0, sizeof(default_runtime));
		strncpy(default_runtime, runtime_dir, sizeof(default_runtime));
	}
	snprintf(port, sizeof(port), "/%d", s->port);
	strcat(default_runtime, port);
	runtime_dir = default_runtime;

	if (access(runtime_dir, R_OK) < 0)
		mkdir_r(runtime_dir, S_IRWXU | S_IRWXG | S_IROTH);

	s->addr.sun_family = AF_LOCAL;
	name_size = snprintf(s->addr.sun_path, sizeof(s->addr.sun_path),
				"%s/%s", runtime_dir, socket_name) + 1;
	s->name = (s->addr.sun_path + name_size - 1) - strlen(socket_name);
	assert(name_size > 0);

	if (name_size > (int)sizeof(s->addr.sun_path)) {
		dprintf(1,"socket path %s/%s plus null terminator"
			" exceed 108 bytes\n", runtime_dir, socket_name);
		errno = ENAMETOOLONG;
		return -1;
	}

	return 0;
}

static int xbus_socket_lock(struct xbus_socket *s)
{
	struct stat socket_stat;

	snprintf(s->lock_addr, sizeof(s->lock_addr),
			"%s%s", s->addr.sun_path, LOCK_SUFFIX);
	s->fd_lock = open(s->lock_addr, O_CREAT | O_CLOEXEC,
			(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP));
	if (s->fd_lock < 0) {
		dprintf(1,"unable to open lockfile %s check permissions\n",
				s->lock_addr);
		goto err;
	}

	if (flock(s->fd_lock, LOCK_EX | LOCK_NB) < 0) {
		dprintf(1,"unable to lock %s file,"
			" maybe another xbus is running\n", s->lock_addr);
		goto err_fd;
	}

	if (stat(s->addr.sun_path, &socket_stat) < 0) {
		if (errno != ENOENT) {
			dprintf(1,"did not manage stat file %s\n",
					s->addr.sun_path);
			goto err_fd;
		}
	} else if (socket_stat.st_mode & S_IWUSR ||
			socket_stat.st_mode & S_IWGRP) {
		unlink(s->addr.sun_path);
	}

	return 0;

err_fd:
	close(s->fd_lock);
	s->fd_lock = -1;
err:
	*s->lock_addr = 0;
	*s->addr.sun_path = 0;

	return -1;
}

static int32_t alloc_xbusid(struct xbus *bus, void *data)
{
	int32_t id;

	id = idr_alloc(&bus->xbusid_idr, data, 0, 0);
	if (id < 0) {
		dprintf(1, "No more free xbusid error %d\n", id);
		abort();
	}

	return id;
}

static inline void free_xbusid(struct xbus *bus, int32_t id)
{
	idr_remove(&bus->xbusid_idr, id);
}

static int32_t alloc_topic_id(struct xbus *bus)
{
	int32_t id;

	id = idr_alloc(&bus->topic_id_idr, bus, 1, 0);
	if (id < 0) {
		dprintf(1, "No more free topic id error %d\n", id);
		abort();
	}

	return id;
}

static void free_topic_id(struct xbus *bus, int32_t id)
{
	idr_remove(&bus->topic_id_idr, id);
}

static struct client_head *find_client_head(struct list_head *list,
		const char *topic)
{
	struct client_head *head;
	int found = 0;

	list_for_each_entry(head, list, entry) {
		if (!strncmp(head->topic, topic, sizeof(head->topic))) {
			found = 1;
			break;
		}
	}

	return found ? head : NULL;
}

static void release_client_head(void *p)
{
	struct client_head *head = p;

	list_del(&head->entry);
	free_topic_id(head->bus, head->id);
	if (head->ispub)
		dprintf(3, "release client pub head %s id %d\n",
				head->topic, head->id);
	else
		dprintf(3, "release client sub/svc head %s id %d\n",
				head->topic, head->id);
	xfree(head);
}

struct client_head *create_client_head(struct xbus *bus, const char *topic)
{
	struct client_head *head;

	head = xmalloc(sizeof(struct client_head));
	check_ptr(head, "No memory to alloc client_head\n");

	memset(head, 0, sizeof(struct client_head));
	vref_init(&head->ref, release_client_head, head);
	strncpy(head->topic, topic, sizeof(head->topic));
	INIT_LIST_HEAD(&head->entry);
	INIT_LIST_HEAD(&head->list);
	head->bus = bus;
	head->id = alloc_topic_id(bus);

	return head;
}

static struct client_container *create_client_container(
		struct xbus_client *client, struct client_head *head)
{
	struct client_container *container;

	container = xmalloc(sizeof(struct client_container));
	check_ptr(container, "No memory to alloc client_container\n");

	memset(container, 0, sizeof(struct client_container));
	INIT_LIST_HEAD(&container->entry);
	INIT_LIST_HEAD(&container->client_entry);
	container->client = client;
	container->head = head;
	head->total++;
	vref_get(&head->ref);

	list_add_tail(&container->entry, &head->list);
	list_add_tail(&container->client_entry, &client->container_list);

	return container;
}

static inline int is_client_linked(struct xbus_client *client, int32_t id)
{
	return idr_find(&client->linked_idr, id) ? 1 : 0;
}

static inline int client_mark_linked(struct xbus_client *client, int32_t id)
{
	return idr_alloc(&client->linked_idr, client, id, id + 1);
}

static inline void client_unlink(struct xbus_client *client, int32_t id)
{
	idr_remove(&client->linked_idr, id);
}

static int send_pub_event(struct xbus_client *sub,
				struct xbus_client *pub, int32_t id,
				int issvc, const char *topic)
{
	struct conn_closure *closure;
	struct xbus_info *minfo;

	if (sub == pub)
		return 0;
	closure = conn_alloc_closure(sub->connection,
				0, sizeof(struct xbus_info));
	check_ptr(closure, "cannot alloc closure for client %s\n", sub->name);

	minfo = closure_data(closure);
	memset(minfo, 0, sizeof(struct xbus_info));
	minfo->id = id;
	minfo->xbusid = pub->xbusid;
	minfo->issvc = issvc;
	dprintf(1, "send xbusid %d to sub %s\n", minfo->xbusid, sub->name);
	strncpy(minfo->name, pub->name, sizeof(minfo->name));
	strncpy(minfo->topic, topic, sizeof(minfo->topic));

	if (!is_client_linked(sub, pub->xbusid)) {
		client_mark_linked(sub, pub->xbusid);
		client_mark_linked(pub, sub->xbusid);

		if (sub->domain != pub->domain) {
			closure->cmd = NODE_CMD_TCP_LINK;
			minfo->port = pub->listening_port;
			memset(minfo->buf, 0, sizeof(minfo->buf));
			strncpy(minfo->buf, pub->domain->ip, sizeof(minfo->buf));
			dprintf(1, "send port %d to sub %s\n",
						minfo->port, sub->name);
		} else {
			closure->cmd = NODE_CMD_UNIX_LINK;
		}
	} else {
		closure->cmd = NODE_CMD_NEW_EVENT;
	}

	xbus_add_msg(sub->bus, sub->connection, closure);

	return 0;
}

static void request_client_port(struct xbus_client *client)
{
	struct conn_closure *closure;

	closure = conn_alloc_closure(client->connection, 0, 0);
	check_ptr(closure, "cannot alloc closure for client %s\n",
						client->name);
	closure->cmd = NODE_CMD_REQ_PORT;
	xbus_add_msg(client->bus, client->connection, closure);
	client->tcp_port_status = TCP_PORT_REQUESTING;
}

static int client_port_notifier(struct notifier_block *nb,
			unsigned long action, void *p)
{
	struct xbus_client *pub;
	struct client_event *ce;

	if (action != NOTIFIER_PORT_READY)
		return NOTIFY_DONE;

	pub = p;
	ce = notifier_get_private(nb);
	if (ce->pub != pub)
		return NOTIFY_DONE;

	send_pub_event(ce->sub, pub, ce->id, ce->issvc, ce->topic);
	xfree(ce);
	nonblocking_unregister_notifier(nb);

	return NOTIFY_DONE;
}

static void register_client_evet(struct xbus_client *sub,
			struct xbus_client *pub, int32_t id,
			int issvc, const char *topic)
{
	struct client_event *ce;

	ce = xmalloc(sizeof(struct client_event));
	check_ptr(ce, "No memory to alloc client event\n");
	memset(ce, 0, sizeof(struct client_event));

	ce->id = id;
	ce->sub = sub;
	ce->pub = pub;
	ce->issvc = issvc;
	strncpy(ce->topic, topic, sizeof(ce->topic));

	pub->tcp_port_status = TCP_PORT_REQUESTING;
	ce->nb.notifier_call = client_port_notifier;
	notifier_set_private(&ce->nb, ce);
	register_notifier(&ce->nb);
}

#if 0
static int domain_acces(struct network_domain *d1, struct network_domain *d2)
{
	char ip1[32] = {0}, ip2[32]={0};
	char *p;

	strncpy(ip1, d1->ip, sizeof(ip1));
	strncpy(ip2, d2->ip, sizeof(ip2));

	p = strrchr(ip1, '.');
	*p = '\0';
	p = strrchr(ip2, '.');
	*p = '\0';

	return !strcmp(ip1, ip2);
}
#endif

static void update_bus_domain(struct xbus *bus)
{
	char iface_name[32];
	char ip[32];

	if (get_iface_name(iface_name, sizeof(iface_name)) == 0) {
		get_local_ip(iface_name, ip);
		if (strcmp(bus->domain->ip, ip)) {
			dprintf(1, "Update bus domain ip to %s\n", ip);
			strncpy(bus->domain->ip, ip, sizeof(bus->domain->ip));
		}
	}
}

static int notify_sub_client(struct xbus_client *sub,
				struct xbus_client *pub, int32_t id,
				int issvc, const char *topic)
{
	if (!is_client_linked(sub, pub->xbusid) &&
				sub->domain != pub->domain) {
		if (pub->domain == pub->bus->domain)
			update_bus_domain(pub->bus);

		switch (pub->tcp_port_status) {
		case TCP_PORT_INVALID:
			request_client_port(pub);
		case TCP_PORT_REQUESTING:
			register_client_evet(sub, pub, id, issvc, topic);
			return 0;
		default:
			break;
		}
	}

	return send_pub_event(sub, pub, id, issvc, topic);
}

static void notify_new_pub(struct xbus *bus, const char *name,
			const char *topic)
{
	struct xbus_client *client;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	list_for_each_entry(client, &bus->client_list, xbus_entry) {
		if (client->pub_ntf == 0)
			continue;
		closure = conn_alloc_closure(client->connection,
				0, sizeof(struct xbus_info));
		check_ptr(closure, "alloc closure error in %s\n", __func__);
		closure->cmd = NODE_CMD_NEW_PUB_NTF;
		minfo = closure_data(closure);
		strncpy(minfo->topic, topic, sizeof(minfo->topic));
		strncpy(minfo->name, name, sizeof(minfo->name));
		xbus_add_msg(bus, client->connection, closure);
	}
}

static int xbus_add_pub(struct xbus *bus, struct xbus_client *client,
					const char *topic)
{
	struct client_head *pub_head, *sub_head;
	struct client_container *container;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	dprintf(3, "client %s add pub %s\n", client->name, topic);
	pub_head = find_client_head(&bus->pub_list, topic);
	if (!pub_head) {
		pub_head = create_client_head(bus, topic);
		if (unlikely(!pub_head)) {
			dprintf(1, "create client head error\n");
			abort();
		}

		pub_head->ispub = 1;
		list_add_tail(&pub_head->entry, &bus->pub_list);

		notify_new_pub(bus, client->name, topic);
		dprintf(1, "distribute id %d to topic %s\n", pub_head->id, topic);
	} else {
		list_for_each_entry(container, &pub_head->list, entry)
			if (container->client == client) {
				dprintf(1, "already add pub client %s\n",
						client->name);
				return 0;
			}
	}

	closure = conn_alloc_closure(client->connection,
				0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	closure->cmd = NODE_CMD_TOPIC_ID;
	minfo = closure_data(closure);
	minfo->id = pub_head->id;
	strncpy(minfo->topic, topic, sizeof(minfo->topic));
	xbus_add_msg(bus, client->connection, closure);

	create_client_container(client, pub_head);

	sub_head = find_client_head(&bus->sub_list, topic);
	if (!sub_head || sub_head->total < 1)
		return 0;

	if (sub_head->id == -1)
		sub_head->id = pub_head->id;

	sub_head->count++;
	pub_head->count++;

	list_for_each_entry(container, &sub_head->list, entry)
		notify_sub_client(container->client, client,
					pub_head->id, 0, topic);

	return 0;
}

static int xbus_add_sub(struct xbus *bus, struct xbus_client *client,
						const char *topic)
{
	struct client_head *pub_head, *sub_head;
	struct client_container *container;

	dprintf(3, "client %s add sub %s\n", client->name, topic);
	sub_head = find_client_head(&bus->sub_list, topic);
	if (!sub_head) {
		sub_head = create_client_head(bus, topic);
		if (unlikely(!sub_head)) {
			dprintf(1, "create client head error\n");
			abort();
		}
		list_add_tail(&sub_head->entry, &bus->sub_list);
	}

	create_client_container(client, sub_head);

	pub_head = find_client_head(&bus->pub_list, topic);
	if (!pub_head || pub_head->total < 1)
		return 0;

	if (sub_head->id == -1)
		sub_head->id = pub_head->id;

	pub_head->count++;
	sub_head->count++;

	list_for_each_entry(container, &pub_head->list, entry)
		notify_sub_client(client, container->client,
					pub_head->id, 0, topic);

	return 0;
}

static void xbus_rm_sub(struct xbus *bus, struct xbus_client *client,
				const char *topic)
{
	struct client_container *ctn;
	struct client_head *h;
	int found = 0;

	h = find_client_head(&bus->sub_list, topic);
	if (h == NULL)
		return;

	list_for_each_entry(ctn, &client->container_list, client_entry) {
		if (ctn->head == h) {
			found = 1;
			break;
		}
	}

	if (!found)
		return;

	list_del(&ctn->entry);
	list_del(&ctn->client_entry);
	h->total--;
	if (h->ispub)
		h = find_client_head(&bus->sub_list,
					ctn->head->topic);
	else
		h = find_client_head(&bus->pub_list,
					ctn->head->topic);
	if (h && h->count)
		h->count--;
	xfree(ctn);
}

static int xbus_add_svc(struct xbus *bus, struct xbus_client *client,
					const char *svc_name)
{
	struct client_head *svc_head, *req_head;
	struct client_container *container;
	struct conn_closure *closure;

	dprintf(3, "client %s New service %s\n", client->name, svc_name);
	svc_head = find_client_head(&bus->svc_list, svc_name);
	if (!svc_head) {
		svc_head = create_client_head(bus, svc_name);
		list_add_tail(&svc_head->entry, &bus->svc_list);

		dprintf(1, "Distribute id %d to service %s\n",
						svc_head->id, svc_name);
	} else {
		list_for_each_entry(container, &svc_head->list, entry)
			if (container->client == client) {
				dprintf(1, "REQ %s already add to client %s\n",
						svc_name, client->name);
				return 0;
			}
	}

	closure = conn_alloc_closure(client->connection,
				0, sizeof(struct xbus_info));
	check_ptr(closure, "alloc closure error in %s\n", __func__);

	create_client_container(client, svc_head);

	req_head = find_client_head(&bus->req_list, svc_name);
	if (!req_head || req_head->total < 1)
		return 0;

	list_for_each_entry(container, &req_head->list, entry)
		notify_sub_client(client, container->client,
					svc_head->id, 1, svc_name);

	return 0;
}

static int xbus_add_req(struct xbus *bus, struct xbus_client *client,
					const char *svc_name)
{
	struct client_head *svc_head, *req_head;
	struct client_container *container;

	dprintf(3, "client %s New request %s\n", client->name, svc_name);
	req_head = find_client_head(&bus->req_list, svc_name);
	if (!req_head) {
		req_head = create_client_head(bus, svc_name);
		dprintf(3, "Add request %s\n", svc_name);
		list_add_tail(&req_head->entry, &bus->req_list);
	} else {
		list_for_each_entry(container, &req_head->list, entry)
			if (container->client == client) {
				dprintf(1, "REQ %s already add to client %s\n",
						svc_name, client->name);
				return 0;
			}
	}

	create_client_container(client, req_head);

	svc_head = find_client_head(&bus->svc_list, svc_name);
	if (!svc_head)
		return 0;

	list_for_each_entry(container, &svc_head->list, entry)
		notify_sub_client(container->client, client,
					svc_head->id, 1, svc_name);

	return 0;
}

static int xbus_report_pub_info(struct xbus *bus, struct xbus_client *client)
{
	struct client_head *head, *head1;
	struct conn_closure *closure;
	struct report_info *rinfo;

	list_for_each_entry(head, &bus->pub_list, entry) {
		closure = conn_alloc_closure(client->connection, 0,
						sizeof(struct report_info));
		check_ptr(closure, "No memory to alloc report info\n");
		closure->cmd = NODE_CMD_PUB_INFO;

		rinfo = closure_data(closure);
		strncpy(rinfo->topic, head->topic, sizeof(rinfo->topic));
		head1 = find_client_head(&bus->sub_list, head->topic);
		if (head1)
			rinfo->count = head1->total;
		else
			rinfo->count = 0;
		xbus_add_msg(bus, client->connection, closure);
	}

	closure = conn_alloc_closure(client->connection, 0,
					sizeof(struct report_info));
	check_ptr(closure, "No memory to alloc report info end\n");
	closure->cmd = NODE_CMD_END;
	xbus_add_msg(bus, client->connection, closure);

	return 0;
}

static void client_destroy(struct xbus_client *client)
{
	struct xbus *bus = client->bus;
	struct xbus_client *client1;
	struct client_head *head;
	struct client_container *ctn, *ctn1;
	struct closure_wrap *cw, *tcw;

	event_source_remove(client->source);
	list_for_each_safe(ctn, ctn1, &client->container_list, client_entry) {
		list_del(&ctn->entry);
		list_del(&ctn->client_entry);
		ctn->head->total--;
		if (ctn->head->count)
			ctn->head->count--;
		if (ctn->head->ispub)
			head = find_client_head(&bus->sub_list,
						ctn->head->topic);
		else
			head = find_client_head(&bus->pub_list,
						ctn->head->topic);
		if (head && head->count)
			head->count--;
		vref_put(&ctn->head->ref);
		xfree(ctn);
	}
	list_del(&client->xbus_entry);

	list_for_each_entry(client1, &bus->client_list, xbus_entry) {
		if (!is_client_linked(client1, client->xbusid))
			continue;
		client_unlink(client1, client->xbusid);
	}

	pthread_mutex_lock(&bus->mutex);
	list_for_each_safe(cw, tcw, &bus->msg_list, entry) {
		if (cw->conn == client->connection) {
			conn_free_closure(cw->conn, cw->closure);
			list_del(&cw->entry);
			xfree(cw);
		}
	}
	pthread_mutex_unlock(&bus->mutex);

	conn_destroy(client->connection);
	close(client->fd);
	dprintf(3, "free client %s id %d\n", client->name, client->xbusid);
	free_xbusid(bus, client->xbusid);
	idr_destroy(&client->linked_idr);
	xfree(client);
}

static int xbus_report_node_info(struct xbus *bus, struct xbus_client *client)
{
	struct xbus_client *client1;
	struct conn_closure *closure;
	struct report_info *rinfo;

	list_for_each_entry(client1, &bus->client_list, xbus_entry) {
		closure = conn_alloc_closure(client->connection, 0,
						sizeof(struct report_info));
		check_ptr(closure, "No memory to alloc for node info\n");
		rinfo = closure_data(closure);

		closure->cmd = NODE_CMD_NODE_INFO;

		strncpy(rinfo->topic, client1->name, sizeof(rinfo->topic));
		xbus_add_msg(bus, client->connection, closure);
	}

	closure = conn_alloc_closure(client->connection, 0,
					sizeof(struct report_info));
	check_ptr(closure, "No memory to alloc for node info end\n");
	closure->cmd = NODE_CMD_END;
	xbus_add_msg(bus, client->connection, closure);

	return 0;
}

static int notify_all_pubs_to_client(struct xbus *bus,
			struct xbus_client *client)
{
	struct client_head *head;
	struct conn_closure *closure;
	struct xbus_info *minfo;

	list_for_each_entry(head, &bus->pub_list, entry) {
		if (head->total < 1)
			continue;

		closure = conn_alloc_closure(client->connection, 0,
						sizeof(struct xbus_info));
		minfo = closure_data(closure);
		closure->cmd = NODE_CMD_NEW_PUB_NTF;
		strncpy(minfo->name, client->name, sizeof(minfo->name));

		memset(minfo->topic, 0, sizeof(minfo->topic));
		strncpy(minfo->topic, head->topic, sizeof(minfo->topic));
		xbus_add_msg(bus, client->connection, closure);
	}

	return 0;
}

int client_conn_handle(int fd, uint32_t mask, void *data)
{
	struct xbus_client *client = (struct xbus_client *)data;
	struct xbus_conn *conn = client->connection;
	struct conn_closure *closure;
	struct xbus_info *minfo;
	int ret;

	if (mask & (EVENT_ERROR | EVENT_HANGUP)) {
		dprintf(1, "mask: %u\n", mask);
		client_destroy(client);
		return 0;
	}

	if (!(mask & EVENT_READABLE))
		return 0;

	ret = conn_read(conn);
	if (ret == -ENETRESET) {
		dprintf(1, "client disconnected %d\n", ret);
		client_destroy(client);
		return 0;
	}

again:
	closure = conn_decode_closure(conn);
	if (closure == NULL)
		return 0;

	minfo = closure_data(closure);
	dprintf(1, "received id %d cmd %d\n", closure->id, closure->cmd);

	switch (closure->cmd) {
	case XBUS_CMD_NODE_NAME:
		sprintf(client->name, "%s", minfo->name);
		dprintf(1, "Received node name %s\n", client->name);
		client->isnamed = 1;
		break;
	case XBUS_CMD_TCP_PORT:
		client->listening_port = minfo->port;
		client->tcp_port_status = TCP_PORT_READY;
		notifier_call_chain(NOTIFIER_PORT_READY, client);
		break;
	case XBUS_CMD_PUB_TOPIC:
		ret = xbus_add_pub(client->bus, client, minfo->topic);
		if (ret < 0)
			dprintf(1, "add publisher error %d\n", ret);

		break;
	case XBUS_CMD_SUB_TOPIC:
		ret = xbus_add_sub(client->bus, client, minfo->topic);
		if (ret < 0)
			dprintf(1, "add suscriber error %d\n", ret);

		break;
	case XBUS_CMD_UNSUB_TOPIC:
		xbus_rm_sub(client->bus, client, minfo->topic);
		break;
	case XBUS_CMD_NEW_SVC:
		ret = xbus_add_svc(client->bus, client, minfo->topic);
		if (ret < 0)
			dprintf(1, "add svc error %d\n", ret);

		break;
	case XBUS_CMD_NEW_REQ:
		ret = xbus_add_req(client->bus, client, minfo->topic);
		if (ret < 0)
			dprintf(1, "add req %s error %d\n", minfo->topic, ret);
		break;
	case XBUS_CMD_GET_PUB:
		xbus_report_pub_info(client->bus, client);
		break;
	case XBUS_CMD_LIST_NODE:
		xbus_report_node_info(client->bus, client);
		break;
	case XBUS_CMD_NEW_PUB_NTF:
		client->pub_ntf = 1;
		dprintf(3, "pub ntf from client %s\n", client->name);
		notify_all_pubs_to_client(client->bus, client);
		break;
	default:
		break;
	}

	conn_free_closure(client->connection, closure);

	goto again;

	return 0;
}

static struct xbus_client *client_create(struct xbus *bus, int fd, int tcp)
{
	struct xbus_client *client;

	client = xmalloc(sizeof(*client));
	if (client == NULL) {
		dprintf(1,"failed to malloc client\n");
		return NULL;
	}
	memset(client, 0, sizeof(struct xbus_client));

	client->bus = bus;
	client->fd = fd;
	client->connection = conn_create(fd, tcp);
	if (!client->connection)
		goto err;

	client->xbusid = alloc_xbusid(bus, client);
	idr_init(&client->linked_idr);
	INIT_LIST_HEAD(&client->xbus_entry);
	INIT_LIST_HEAD(&client->container_list);
	client->source = event_loop_add_fd(bus->loop, fd,
				EVENT_READABLE,
				client_conn_handle, client);

	list_add(&client->xbus_entry, &bus->client_list);

	return client;

err:
	xfree(client);

	return NULL;
}

static int socket_data(int fd, uint32_t mask, void *data)
{
	struct xbus *bus = (struct xbus *)data;
	struct xbus_client *client;
	struct sockaddr_un name;
	socklen_t length;
	int client_fd;

	if ((mask & EVENT_READABLE) != 1)
		return -1;

	length = sizeof(name);
	client_fd = os_accept_cloexec(fd, (struct sockaddr *)&name, &length);
	if (client_fd < 0) {
		dprintf(1,"failed to accept\n");
		return 0;
	}

	client = client_create(bus, client_fd, 0);
	if (!client) {
		dprintf(1, "cannot create xbus client\n");
		return 0;
	}

	client->domain = bus->domain;

	return 0;
}

struct network_domain *create_net_domain(struct xbus *bus, const char *ip)
{
	struct network_domain *domain;

	list_for_each_entry(domain, &bus->domain_list, entry)
		if (!strncmp(domain->ip, ip, sizeof(domain->ip)))
			return domain;

	domain = xmalloc(sizeof(struct network_domain));
	check_ptr(domain, "No memory to alloc network_domain\n");
	memset(domain, 0, sizeof(struct network_domain));

	INIT_LIST_HEAD(&domain->entry);
	list_add_tail(&domain->entry, &bus->domain_list);
	strncpy(domain->ip, ip, sizeof(domain->ip));
	dprintf(3, "Add new network domain %s\n", domain->ip);

	return domain;
}

static int tcp_socket_data(int fd, uint32_t mask, void *data)
{
	struct xbus *bus = (struct xbus *)data;
	struct xbus_client *client;
	struct sockaddr_in addr;
	socklen_t length;
	int client_fd;

	if ((mask & EVENT_READABLE) != 1)
		return -1;

	length = sizeof(addr);
	client_fd = os_accept_cloexec(fd, (struct sockaddr *)&addr, &length);
	if (client_fd < 0) {
		dprintf(1,"failed to accept\n");
		goto out;
	}

	client = client_create(bus, client_fd, 1);
	if (!client) {
		dprintf(1, "cannot create xbus client\n");
		goto out;
	}

	client->domain = create_net_domain(bus, inet_ntoa(addr.sin_addr));
	dprintf(3, "Accept socket port ip %s\n", client->domain->ip);

out:
	return 0;
}

static int create_tcp_socket(struct xbus *bus, struct xbus_socket *s)
{
	struct sockaddr_in in_addr;
	int ret;

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(s->port);
	in_addr.sin_addr.s_addr = INADDR_ANY;

	s->tfd = os_socket_cloexec(AF_INET, SOCK_STREAM, 0);
	if (s->tfd < 0)
		return s->tfd;

	if (setsockopt(s->tfd, SOL_SOCKET, SO_REUSEADDR, &ret,
						sizeof(ret)) < 0)
		dprintf(2, "set socket SO_REUSEADDR error\n");

	ret = bind(s->tfd, (struct sockaddr *)&in_addr,
				sizeof(struct sockaddr_in));
	if (ret < 0) {
		printf("bind sockfd error\n");
		goto err_close_tcp_socket;
	}

	ret = listen(s->tfd, 1024);
	if (ret < 0) {
		dprintf(1, "listen error\n");
		goto err_close_tcp_socket;
	}

	s->tcp_source = event_loop_add_fd(bus->loop, s->tfd,
					EVENT_READABLE,
					tcp_socket_data, bus);
	if (s->tcp_source == NULL)
		goto err_close_tcp_socket;

	return 0;

err_close_tcp_socket:
	close(s->tfd);

	return -1;
}

static void destroy_tcp_socket(struct xbus_socket *s)
{
	if (s->tcp_source)
		event_source_remove(s->tcp_source);
	close(s->tfd);
}

static int create_unix_socket(struct xbus *bus, struct xbus_socket *s)
{
	socklen_t size;

	s->fd = os_socket_cloexec(PF_LOCAL, SOCK_STREAM, 0);
	if (s->fd < 0)
		return -1;

	size = offsetof(struct sockaddr_un, sun_path) + strlen(s->addr.sun_path);
	if (bind(s->fd, (struct sockaddr *)&s->addr, size) < 0) {
		dprintf(1,"bind() failed with error\n");
		goto err_close_unix_socket;
	}

	if (listen(s->fd, 1024) < 0) {
		dprintf(1,"listen() failed with erros\n");
		goto err_close_unix_socket;
	}

	s->source = event_loop_add_fd(bus->loop, s->fd,
					EVENT_READABLE,
					socket_data, bus);
	if (s->source == NULL)
		goto err_close_unix_socket;


	return 0;

err_close_unix_socket:
	close(s->fd);

	return -1;
}

static void destroy_unix_socket(struct xbus_socket *s)
{
	if (s->source)
		event_source_remove(s->source);
	close(s->fd);
}

static void xbus_socket_destroy(struct xbus_socket *s)
{
	destroy_unix_socket(s);
	destroy_tcp_socket(s);
	xfree(s);
}

static int _xbus_add_socket(struct xbus *bus, struct xbus_socket *s)
{
	int ret;

	ret = create_unix_socket(bus, s);
	if (ret < 0) {
		dprintf(1, "Create unix socket error %d\n", ret);
		return ret;
	}

	ret = create_tcp_socket(bus, s);
	if (ret < 0) {
		dprintf(1, "Create tcp socket error %d\n", ret);
		goto err_destroy_unix_socket;
	}

	return 0;

err_destroy_unix_socket:
	destroy_unix_socket(s);

	return ret;
}

static int xbus_add_socket(struct xbus *bus, const char *socket_name)
{
	struct xbus_socket *s;

	s = xbus_socket_alloc();
	if (s == NULL)
		return -1;

	if (xbus_socket_set_name(s, socket_name) < 0)
		goto err;

	if (xbus_socket_lock(s) < 0)
		goto err;

	if (_xbus_add_socket(bus, s) < 0)
		goto err;

	return 0;
err:
	xbus_socket_destroy(s);

	return -1;
}

static char *xbus_add_socket_auto(struct xbus *bus)
{
	struct xbus_socket *s;
	char socket_name[16];

	s = xbus_socket_alloc();
	if (s == NULL)
		return NULL;

	snprintf(socket_name, sizeof(socket_name), "bus-%d", 0);
	dprintf(4,"socket_name: %s\n", socket_name);
	if (xbus_socket_set_name(s, socket_name) < 0)
		goto err;

	if (xbus_socket_lock(s) < 0)
		goto err;

	if (_xbus_add_socket(bus, s) < 0)
		goto err;

	return s->name;

err:
	xbus_socket_destroy(s);

	return NULL;
}

static int xbus_create_listening_socket(struct xbus *bus,
					char *socket_name)
{
	if (socket_name) {
		if (xbus_add_socket(bus, socket_name) < 0) {
			dprintf(1,"failed to add socket.\n");
			return -1;
		}
	} else {
		socket_name = xbus_add_socket_auto(bus);
		if (socket_name == NULL) {
			dprintf(1,"failed to add socket auto.\n");
			xfree(socket_name);
			return -1;
		}
	}

	setenv("XBUS2_SOCKET", socket_name, 1);

	return 0;
}

static int check_write_msg(void *p)
{
	struct xbus *bus = p;
	int ret = 1;

	pthread_mutex_lock(&bus->mutex);
	if (list_empty(&bus->msg_list))
		ret = 0;
	pthread_mutex_unlock(&bus->mutex);

	return ret;
}

static void *xbus_write_thread(void *p)
{
	struct xbus *bus = p;
	struct closure_wrap *cw, *tcw;
	int ret;

	for (;;) {
		wait_for_completion_timeout(&bus->write_completion, 2,
				check_write_msg, bus);

		pthread_mutex_lock(&bus->mutex);
		list_for_each_safe(cw, tcw, &bus->msg_list, entry) {
			ret = conn_send_closure(cw->conn, cw->closure, 0);
			if (ret < 0 && ret != -ENETRESET)
				continue;

			conn_free_closure(cw->conn, cw->closure);
			list_del(&cw->entry);
			xfree(cw);
		}
		pthread_mutex_unlock(&bus->mutex);
		conn_flush_all();
	}

	return (void *)0;
}

XBUS_EXPORT int xbus_init_s(void)
{
	struct xbus *bus;
	char *master_ip;
	char iface_name[32];
	int ret;

	/*
	 *fflush(stdout);
	 *setvbuf(stdout, NULL, _IONBF, 0);
	 *int save_fd = dup(STDOUT_FILENO);
	 *int fd = open("log.txt", (O_RDWR | O_CREAT), 0644);
	 *dup2(fd, STDOUT_FILENO);
	 *dprintf(4,"testlfdkkdfkj\n");
	 */
	log_file_open(NULL);
	dprintf(1, "XBUS VERSION: %s\n", CONFIG_VERSION);
	dprintf(1, "\tUTS_VERSION: %s\n", UTS_VERSION);
	dprintf(1, "\tXBUS COMMIT: %s\n", XBUS_COMMIT);
	dprintf(1, "\tXBUS HOST INFO: %s@%s\n",
			XBUS_COMPILE_BY, XBUS_COMPILE_HOST);
	dprintf(1, "\tXBUS COMPILER: %s\n", XBUS_COMPILER);
	mem_init();
	bus = xzmalloc(sizeof(*bus));
	if (bus == NULL) {
		dprintf(1,"Failed to alloc bus.\n");
		return -1;
	}

	init_completion(&bus->write_completion);
	pthread_mutex_init(&bus->mutex, NULL);

	notifier_head_init();
	/* topic id start from 1 */
	idr_init(&bus->topic_id_idr);
	idr_init(&bus->xbusid_idr);
	INIT_LIST_HEAD(&bus->pub_list);
	INIT_LIST_HEAD(&bus->sub_list);
	INIT_LIST_HEAD(&bus->svc_list);
	INIT_LIST_HEAD(&bus->req_list);
	INIT_LIST_HEAD(&bus->client_list);
	INIT_LIST_HEAD(&bus->domain_list);
	INIT_LIST_HEAD(&bus->msg_list);
	bus->loop = event_loop_create();
	if (bus->loop->epoll_fd < 0) {
		dprintf(1,"Failed to create epoll fd.\n");
		goto err_free_mem;
	}

	master_ip = getenv("XBUS2_MASTER_IP");
	if (master_ip) {
		master_ip = strtok(master_ip, ":");
		bus->domain = create_net_domain(bus, master_ip);
	} else {
		bus->domain = create_net_domain(bus, "127.0.0.1");
	}
	if (get_iface_name(iface_name, sizeof(iface_name)) == 0)
		get_local_ip(iface_name, bus->domain->ip);

	xbus = bus;

	ret = hthread_create(&bus->tid, "write", xbus_write_thread, bus);
	if (ret < 0) {
		dprintf(1, "create thread error %d\n", ret);
		goto err_free_mem;
	}

	if (xbus_create_listening_socket(bus, NULL) < 0)
		goto err_free_mem;

	return 0;

err_free_mem:
	xfree(bus);

	return -1;
}

XBUS_EXPORT void xbus_run_s()
{
	struct xbus *bus;
	struct timeval start;
	struct timeval end;
	int i = 0, hz;
	double total;

	bus = get_xbus();

	if (bus->run != 0) {
		dprintf(1,"another bus is running\n");
		return;
	}

	bus->run = 1;

	gettimeofday(&start, 0);
	while (bus->run) {
		event_loop_dispatch(bus->loop, -1);
		i++;
		if (i == 2000) {
			gettimeofday(&end, 0);
			total = (end.tv_sec - start.tv_sec) * 1000000 +
				end.tv_usec - start.tv_usec;
			hz = 2000 / total;
			dprintf(4, "hz: %d\n", hz);
			gettimeofday(&start, 0);
			i = 0;
		}
	}
}
