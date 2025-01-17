/*
 *        > File Name: connection.c
 *        > Author: zhujiongfu
 *        > Mail: zhujiongfu@live.cn
 *        > Created Time: Sat 09 Jun 2018 04:26:31 PM CST
 *
 */
#include <pthread.h>
#define THIS_MODULE 	"CONN"

#include <unistd.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <string.h>

#include <wrapper.h>
#include <log.h>
#include <os.h>
#include <log2.h>
#include <uapi/error.h>

#include "xbus-protocol.h"
#include "xbus-conn.h"

#define DIV_ROUNDUP(n, a) ((n + (a - 1)) / a)

#define MAX_FDS_OUT 8
#define CLEN            (CMSG_LEN(MAX_FDS_OUT * sizeof(int32_t)))

#define HEADER_MAGIC 	((uint32_t)('m' << 24) | ('a' << 16) \
		| ('g' << 8) | ('a'))
#define TAIL_MAGIC	((uint32_t)('t') << 24 | ('a' << 16) \
		| ('i' << 8) | ('l'))
#define XBUS_PROTOCOL 	0x01

#define CONN_BUFFER_SIZE 	4096
#define CONN_BIG		256

struct packet_header {
	int32_t 		version;
	int32_t			size;
	uint16_t 		id;
	uint16_t		opt_id1;
	uint16_t		opt_id2;
	int8_t			cmd;
	uint32_t		magic;
};

struct closure_zone {
	struct list_head	free_list;
	struct list_head	all_list;
	int32_t			free_cnt;
	int32_t			max_free_cnt;
	int32_t			total_cnt;
	int32_t 		total_size;
};

static LIST_HEAD(conn_list);
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

static void conn_lock(struct xbus_conn *conn)
{
	pthread_mutex_lock(&conn->mutex);
}

static void conn_unlock(struct xbus_conn *conn)
{
	pthread_mutex_unlock(&conn->mutex);
}

static struct conn_buffer *alloc_conn_buffer(size_t size)
{
	struct conn_buffer *b;

	size = roundup_pow_of_two(size);
	b = xzmalloc(sizeof(struct conn_buffer) + size + 8);
	check_ptr(b, "No memory for conn_buffer\n");

	b->data = (uint8_t *)b + sizeof(struct conn_buffer);
	b->size = size;
	b->mask = size - 1;
	b->head = 0;
	b->tail = 0;

	return b;
}

static inline void destroy_conn_buffer(struct conn_buffer *b)
{
	xfree(b);
}

struct xbus_conn *conn_create(int fd, int have_tail)
{
	struct xbus_conn *conn;
	int ret;

	conn = (struct xbus_conn *)xmalloc(sizeof(*conn) + 128);
	if (conn == NULL)
		return NULL;

	memset(conn, 0, sizeof(*conn));

	INIT_LIST_HEAD(&conn->entry);
	if (have_tail)
		conn->have_tail = 4;
	/* conn->have_tail = 1; */
	conn->in = alloc_conn_buffer(CONN_BUFFER_SIZE);
	conn->out = alloc_conn_buffer(CONN_BUFFER_SIZE);
	conn->in_fds = alloc_conn_buffer(128);
	conn->out_fds = alloc_conn_buffer(128);
	conn->hdr_buf = (char *)conn + sizeof(*conn);
	idr_init(&conn->zone_idr);
	ret = pthread_mutex_init(&conn->mutex, NULL);
	if (ret < 0) {
		dprintf(1, "init mutex error\n");
		goto err_free_mem;
	}

	ret = pthread_mutex_init(&conn->send_mutex, NULL);
	if (ret < 0) {
		dprintf(1, "init mutex error\n");
		goto err_mutex_destroy;
	}

	ret = pthread_cond_init(&conn->cond, NULL);
	if (ret < 0) {
		dprintf(1, "init pthread cond error %d\n", ret);
		goto err_send_mutex_destroy;
	}

	conn->fd = os_dupfd_cloexec(fd, 0);
	if (conn->fd < 0) {
		dprintf(1, "dupfd error %d\n", -errno);
		goto err_cond_destroy;
	}

	pthread_mutex_lock(&conn_mutex);
	list_add(&conn->entry, &conn_list);
	pthread_mutex_unlock(&conn_mutex);

	return conn;

err_cond_destroy:
	pthread_cond_destroy(&conn->cond);
err_send_mutex_destroy:
	pthread_mutex_destroy(&conn->send_mutex);
err_mutex_destroy:
	pthread_mutex_destroy(&conn->mutex);
err_free_mem:
	xfree(conn);

	return NULL;
}

void conn_get(struct xbus_conn *conn)
{
	pthread_mutex_lock(&conn->mutex);
	conn->refcnt++;
	pthread_mutex_unlock(&conn->mutex);
}

void conn_put(struct xbus_conn *conn)
{
	pthread_mutex_lock(&conn->mutex);
	conn->refcnt--;
	if (conn->refcnt < 1) {
		pthread_mutex_unlock(&conn->mutex);
		dprintf(3, "destroy conn\n");
		conn_destroy(conn);
	} else {
		pthread_mutex_unlock(&conn->mutex);
	}
}

static struct conn_closure *create_closure(size_t size)
{
	struct conn_closure *closure;

	closure = xmalloc(sizeof(struct conn_closure) + size + 8);
	if (closure == NULL) {
		dprintf(1, "malloc closure error\n");
		return NULL;
	}

	memset(closure, 0x00, sizeof(*closure));

	INIT_LIST_HEAD(&closure->entry);
	INIT_LIST_HEAD(&closure->all_entry);
	closure->state = CLOSURE_STATE_HEADER;
	closure->len = size;
	closure->buf_size = size;
	closure->buf = (char *)closure + sizeof(*closure);

	return closure;
}

static void destroy_closure(struct conn_closure *closure)
{
	list_del(&closure->entry);
	list_del(&closure->all_entry);
	xfree(closure);
}

static void zone_free_closure(struct closure_zone *zone,
		struct conn_closure *closure)
{
	if (zone->free_cnt > zone->max_free_cnt) {
		zone->total_cnt--;
		zone->total_size -= closure->len;
		destroy_closure(closure);
	} else {
		list_add_tail(&closure->entry, &zone->free_list);
		zone->free_cnt++;
	}
}

static struct conn_closure *zone_find_best_closure(struct closure_zone *zone,
		int32_t id, size_t size)
{
	struct conn_closure *closure;
	int found = 0;

	list_for_each_entry(closure, &zone->free_list, entry) {
		if (closure->buf_size >= size
			&& size < (closure->buf_size >> 1)
				+ closure->buf_size) {
			found = 1;
			break;
		}
	}

	if (found) {
		list_del(&closure->entry);
		closure->len = size;
		closure->fds_len = 0;
		closure->offset = 0;
		closure->hdr_offset = 0;
		closure->write_offset = 0;
		closure->read_offset = 0;
		closure->state = CLOSURE_STATE_HEADER;
		zone->free_cnt--;
		return closure;
	}

	closure = create_closure(size);
	if (closure == NULL)
		return NULL;

	closure->id = id;
	zone->total_size += size;
	zone->total_cnt++;
	list_add(&closure->all_entry, &zone->all_list);

	return closure;
}

struct conn_closure *conn_alloc_closure(struct xbus_conn *conn,
		int32_t id, size_t size)
{
	struct closure_zone *zone;
	struct conn_closure *closure;
	int ret;

	conn_lock(conn);
	zone = idr_find(&conn->zone_idr, id);
	if (zone == NULL) {
		zone = xmalloc(sizeof(struct closure_zone));
		if (zone == NULL) {
			dprintf(1, "alloc memory for closure_zone error\n");
			conn_unlock(conn);
			return NULL;
		}

		memset(zone, 0x00, sizeof(struct closure_zone));

		zone->max_free_cnt = 10;
		INIT_LIST_HEAD(&zone->free_list);
		INIT_LIST_HEAD(&zone->all_list);

		ret = idr_alloc(&conn->zone_idr, zone, id, id + 1);
		if (ret < 0) {
			dprintf(1, "unable to alloc zone idr for id %d\n", id);
			goto err_free_zone;
		}
	}

	closure = zone_find_best_closure(zone, id, size);
	conn_unlock(conn);

	return closure;

err_free_zone:
	conn_unlock(conn);
	xfree(zone);

	return NULL;
}

void conn_free_closure(struct xbus_conn *conn, struct conn_closure *closure)
{
	struct closure_zone *zone;

	conn_lock(conn);
	if (closure->refcnt) {
		closure->refcnt--;
		conn_unlock(conn);
		return;
	}

	zone = idr_find(&conn->zone_idr, closure->id);
	check_ptr(zone, "invalid closure id %d to free\n", closure->id);

	zone_free_closure(zone, closure);
	conn_unlock(conn);
}

void conn_closure_ref(struct xbus_conn *conn, struct conn_closure *closure)
{
	conn_lock(conn);
	closure->refcnt++;
	conn_unlock(conn);
}

static void conn_buffer_put_iov(struct conn_buffer *b,
				struct iovec *iov, int *count)
{
	uint16_t head, tail;

	head = b->head & b->mask;
	tail = b->tail & b->mask;
	if (head < tail) {
		iov[0].iov_base = b->data + head;
		iov[0].iov_len = tail - head;
		*count = 1;
	} else if (tail == 0) {
		iov[0].iov_base = b->data + head;
		iov[0].iov_len = b->size - head;
		*count = 1;
	} else {
		iov[0].iov_base = b->data + head;
		iov[0].iov_len = b->size - head;
		iov[1].iov_base = b->data;
		iov[1].iov_len = tail;
		*count = 2;
	}
}

static void conn_buffer_get_iov(struct conn_buffer *b,
				struct iovec *iov, int *count)
{
	uint16_t head, tail;

	head = b->head & b->mask;
	tail = b->tail & b->mask;
	if (tail < head) {
		iov[0].iov_base = b->data + tail;
		iov[0].iov_len = head - tail;
		*count = 1;
	} else if (head == 0) {
		iov[0].iov_base = b->data + tail;
		iov[0].iov_len = b->size - tail;
		*count = 1;
	} else {
		iov[0].iov_base = b->data + tail;
		iov[0].iov_len = b->size - tail;
		iov[1].iov_base = b->data;
		iov[1].iov_len = head;
		*count = 2;
	}
}

static int conn_buffer_in(struct conn_buffer *b,
				const void *data, uint32_t count)
{
	uint16_t head, size;

	if (count > b->size) {
		dprintf(1, "Data too big for buffer (%u > %u).\n",
		       count, b->size);
		errno = E2BIG;
		return -1;
	}

	head = b->head & b->mask;
	if (head + count <= b->size) {
		memcpy(b->data + head, data, count);
	} else {
		size = b->size - head;
		memcpy(b->data + head, data, size);
		memcpy(b->data, (const char *) data + size, count - size);
	}

	b->head += count;
	if ((b->head & b->mask) == (b->tail & b->mask))
		b->full = 1;

	return 0;
}

static uint16_t conn_buffer_used(struct conn_buffer *b)
{
	if (b->full)
		return b->size;
	return (b->head - b->tail) & b->mask;
}

static int can_conn_buffer_in(struct conn_buffer *b, uint32_t size)
{
	if (b->full)
		return 0;
	return (uint16_t)(b->head - b->tail) + size > b->size ? 0 : 1;
}

static void conn_buffer_copy(struct conn_buffer *b, void *data, uint32_t count)
{
	uint16_t tail, size;

	tail = b->tail & b->mask;
	if (tail + count <= b->size) {
		memcpy(data, b->data + tail, count);
	} else {
		size = b->size - tail;
		memcpy(data, b->data + tail, size);
		memcpy((char *) data + size, b->data, count - size);
	}
}

static void conn_buffer_out(struct conn_buffer *b, void *data, size_t count)
{
	conn_buffer_copy(b, data, count);
	b->tail += count;
	b->full = 0;
}

static inline void conn_buffer_clear(struct conn_buffer *b)
{
	b->tail = 0;
	b->head = 0;
	b->full = 0;
}

static void build_cmsg(struct conn_buffer *b, char *data, int *clen)
{
	struct cmsghdr *cmsg;
	size_t size;

	size = conn_buffer_used(b);
	if (size > 0) {
		cmsg = (struct cmsghdr *) data;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(size);
		conn_buffer_out(b, CMSG_DATA(cmsg), size);
		*clen = cmsg->cmsg_len;
	} else {
		*clen = 0;
	}
}

static int decode_cmsg(struct conn_buffer *b, struct msghdr *msg)
{
	struct cmsghdr *cmsg;
	size_t size, i;
	int overflow = 0;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
		cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
			cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		size = cmsg->cmsg_len - CMSG_LEN(0);
		dprintf(1, "cmsg size %d\n", size);
		if (!can_conn_buffer_in(b, size) || overflow) {
			overflow = 1;
			size /= sizeof(int32_t);
			for (i = 0; i < size; i++)
				close(((int *)CMSG_DATA(cmsg))[i]);
		} else if (conn_buffer_in(b, CMSG_DATA(cmsg), size) < 0) {
			return -1;
		}
	}

	if (overflow) {
		errno = EOVERFLOW;
		return -1;
	}

	return 0;
}

static int conn_read_to_buffer(struct xbus_conn *conn)
{
	struct iovec iov[2];
	struct msghdr msg;
	char cmsg[CLEN];
	struct conn_buffer *b = conn->in;
	int count;
	int len;
	int ret;

	if (conn_buffer_used(b) >= b->size)
		return -EOVERFLOW;

	conn_buffer_put_iov(b, iov, &count);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = count;
	msg.msg_control = cmsg;
	msg.msg_controllen = sizeof(cmsg);
	msg.msg_flags = 0;

	do {
		len = os_recvmsg_cloexec(conn->fd, &msg, MSG_DONTWAIT);
	} while (len < 0 && errno == EINTR);

	if (len == 0) {
		dprintf(3, "remote socket is shutdown\n");
		return -ENETRESET;
	}

	if (len < 0)
		return len;

	ret = decode_cmsg(conn->in_fds, &msg);
	if (ret < 0) {
		dprintf(1, "decode socket cmsg error %d\n", ret);
		return ret;
	}

	b->head += len;
	if ((b->head & b->mask) == (b->tail & b->mask))
		b->full = 1;

	return conn_buffer_used(b);
}

static int conn_read_to_closure(struct xbus_conn *conn,
			struct conn_closure *closure)
{
	struct iovec iov;
	struct msghdr msg;
	int len;
	int extra = 0;

	if (conn->have_tail)
		extra = 4;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	iov.iov_base = closure->buf + closure->offset;
	iov.iov_len = closure->len - closure->offset + extra;

	do {
		len = os_recvmsg_cloexec(conn->fd, &msg, MSG_DONTWAIT);
	} while (len < 0 && errno == EINTR);

	if (len == 0) {
		dprintf(3, "remote socket is shutdown\n");
		return -ENETRESET;
	}

	if (len < 0)
		return len;

	closure->offset += len;

	if (closure->offset != closure->len + extra)
		return 0;

	if (conn->have_tail && *((uint32_t *)&closure->buf[closure->len])
				!= TAIL_MAGIC) {
		conn->stage = CONN_DECODE_HEADER;
		conn->recv_closure = NULL;
		conn_free_closure(conn, closure);
		dprintf(1, "Received incorrect packet!!\n");
		return 0;
	}

	conn->stage = CONN_DECODE_DATA_END;

	return 0;
}

int conn_read(struct xbus_conn *conn)
{
	if (conn->stage == CONN_DECODE_DATA_BIG)
		return conn_read_to_closure(conn, conn->recv_closure);

	return conn_read_to_buffer(conn);
}

struct conn_closure *conn_decode_closure(struct xbus_conn *conn)
{
	struct packet_header header = {0};
	struct conn_closure *closure;
	int extra = 0;
	size_t size;
	uint32_t remain;

	if (conn->stage == CONN_DECODE_DATA_END) {
		conn->stage = CONN_DECODE_HEADER;
		closure = conn->recv_closure;
		conn->recv_closure = NULL;
		return closure;
	}

	if (conn->stage == CONN_DECODE_HEADER) {
		if (conn_buffer_used(conn->in) < sizeof(header))
			return NULL;

		conn_buffer_out(conn->in, &header, sizeof(header));
		if (header.magic != HEADER_MAGIC) {
			dprintf(3, "magic %x\n", header.magic);
			dprintf(3, "received invalid header info!!\n");
			conn_buffer_clear(conn->in);
			conn_buffer_clear(conn->in_fds);
			return NULL;
		}

		dprintf(4, "decode id %d, size %d\n", header.id, header.size);
		closure = conn_alloc_closure(conn, header.id, header.size);
		check_ptr(closure, "alloc closure error\n");
		closure->cmd = header.cmd;
		closure->opt_id1 = header.opt_id1;
		closure->opt_id2 = header.opt_id2;
		conn->recv_closure = closure;

		if (closure->cmd == BP_CMD_NEW_SHM) {
			conn_buffer_out(conn->in_fds,
					&closure->fds, sizeof(int));
			closure->fds_len = sizeof(int);
		}

		size = conn_buffer_used(conn->in);
		if (closure->len > size) {
			remain = closure->len - size;
			if (remain >= CONN_BIG) {
				conn->stage = CONN_DECODE_DATA_BIG;
				conn_buffer_out(conn->in, closure->buf, size);
				closure->offset = size;
				return NULL;
			}
		}
		conn->stage = CONN_DECODE_DATA;
	} else {
		closure = conn->recv_closure;
	}

	if (conn->have_tail)
		extra = 4;

	remain = closure->len - closure->offset + extra;
	size = conn_buffer_used(conn->in);
	if (remain > size)
		remain = size;

	if (closure->offset + remain > closure->buf_size + extra) {
		dprintf(1, "offset %u is over the buf size %u\n",
				closure->offset, closure->buf_size);
		abort();
	}

	conn_buffer_out(conn->in, closure->buf + closure->offset, remain);
	closure->offset += remain;
	if (closure->offset != closure->len + extra)
		return NULL;

	conn->recv_closure = NULL;
	conn->stage = CONN_DECODE_HEADER;

	if (conn->have_tail && *((uint32_t *)&closure->buf[closure->len])
				!= TAIL_MAGIC) {
		dprintf(1, "Received incorrect packet!!\n");
		conn_buffer_clear(conn->in);
		conn_buffer_clear(conn->in_fds);
		conn_free_closure(conn, closure);
		return NULL;
	}

	return closure;
}

/*
 * static void close_fds(struct conn_closure *closure)
 * {
 *         int i;
 *
 *         for (i = 0; i < closure->fds_len; i++)
 *                 close(closure->fds[i]);
 * }
 */

static void conn_wait(struct xbus_conn *conn)
{
	for (;;) {
		conn->waiters++;
		pthread_cond_wait(&conn->cond, &conn->send_mutex);
		if (conn->have_pending == 0)
			break;
	}
	conn->waiters--;
}

static int conn_sendmsg(struct xbus_conn *conn, struct msghdr *msg, int flags)
{
	int skt_flags = MSG_DONTWAIT;
	int len = 0;
	int total = 0;
	int i;
	int ret;

	if (flags)
		skt_flags = 0;

	for (i = 0; i < msg->msg_iovlen; i++)
		len += msg->msg_iov[i].iov_len;

	do {
		ret = sendmsg(conn->fd, msg, MSG_NOSIGNAL | skt_flags);
		if (ret == -1) {
			if (errno == EAGAIN && flags) {
				usleep(5000);
				continue;
			} else if (errno == EINTR) {
				continue;
			} else {
				ret = -errno;
				break;
			}
		}

		total += ret;
		if (ret == len || flags == 0) {
			if (ret == 0)
				ret = -1;
			break;
		}
		len -= ret;
		for (i = 0; i < msg->msg_iovlen; i++) {
			if (msg->msg_iov[i].iov_len > ret) {
				msg->msg_iov[i].iov_len -= ret;
				msg->msg_iov[i].iov_base += ret;
				break;
			}

			ret -= msg->msg_iov[i].iov_len;
			if (ret == 0)
				break;
		}

		msg->msg_iov += i;
		msg->msg_iovlen -= i;

	} while (1);

	return total > 0 ? total : ret;
}

static int conn_flush(struct xbus_conn *conn, int flags)
{
	struct iovec iov[2];
	struct msghdr msg;
	char cmsg[CLEN];
	struct conn_buffer *b = conn->out;
	int skt_flags = MSG_DONTWAIT;
	int len = 0, count, clen;
	uint16_t tail;
	int retry = 5;

	if (!READ_ONCE(conn->want_flush))
		return 0;

	if (flags)
		skt_flags = 0;

	tail = b->tail;
	while (conn_buffer_used(b) > 0) {
		conn_buffer_get_iov(b, iov, &count);

		build_cmsg(conn->out_fds, cmsg, &clen);

		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = count;
		msg.msg_control = (clen > 0) ? cmsg : NULL;
		msg.msg_controllen = clen;
		msg.msg_flags = 0;

		do {
			len = sendmsg(conn->fd, &msg,
				      MSG_NOSIGNAL | skt_flags);
		} while (len == -1 && errno == EINTR);

		if (len == -1) {
			if (errno == EAGAIN && retry--)
				continue;
			return -errno;
		}

		b->tail += len;
		if (len)
			b->full = 0;
		if (clen)
			conn_buffer_clear(conn->out_fds);
	}

	WRITE_ONCE(conn->want_flush, 0);

	return conn_buffer_used(b);
}

void conn_flush_all(void)
{
	struct xbus_conn *conn;

	pthread_mutex_lock(&conn_mutex);
	list_for_each_entry(conn, &conn_list, entry) {
		pthread_mutex_lock(&conn->send_mutex);
		WRITE_ONCE(conn->want_flush, 1);
		conn_flush(conn, 0);
		pthread_mutex_unlock(&conn->send_mutex);
	}
	pthread_mutex_unlock(&conn_mutex);
}

static int conn_send_small_closure(struct xbus_conn *conn,
			struct conn_closure *closure, int flags)
{
	struct packet_header header;
	struct conn_buffer *b = conn->out;
	uint32_t avail;
	uint32_t data_len;
	int ret;

	pthread_mutex_lock(&conn->send_mutex);
	if (conn->have_pending && conn->send_closure != closure) {
		if (flags) {
			conn_wait(conn);
		} else {
			pthread_mutex_unlock(&conn->send_mutex);
			return -1;
		}
	}

	if (closure->state == CLOSURE_STATE_HEADER) {
		if (!can_conn_buffer_in(b, sizeof(header))) {
			WRITE_ONCE(conn->want_flush, 1);
			ret = conn_flush(conn, flags);
			if (ret < 0) {
				pthread_mutex_unlock(&conn->send_mutex);
				return ret;
			}
		}

		if (!can_conn_buffer_in(b, sizeof(header))) {
			pthread_mutex_unlock(&conn->send_mutex);
			return -1;
		}

		if (closure->fds_len > 0)
			conn_buffer_in(conn->out_fds,
					&closure->fds, sizeof(int));
		/* send header info first */
		header.id = closure->id;
		header.opt_id1 = closure->opt_id1;
		header.opt_id2 = closure->opt_id2;
		header.size = closure->len;
		header.cmd = closure->cmd;
		header.magic = HEADER_MAGIC;

		conn_buffer_in(b, &header, sizeof(header));
		closure->state = CLOSURE_STATE_DATA;
		if (conn->have_tail)
			*((uint32_t *)&closure->buf[closure->len]) = TAIL_MAGIC;
	}

	if (conn->have_tail)
		data_len = closure->len + 4 - closure->offset;
	else
		data_len = closure->len - closure->offset;

	dprintf(4, "data_len %u offset %u len %u\n",
			data_len, closure->offset, closure->len);
	if (flags & CONN_NO_PENDING) {
		conn->have_pending = 0;
		conn->send_closure = NULL;
	} else {
		conn->have_pending = 1;
		conn->send_closure = closure;
	}

	do {
		if (b->full) {
			WRITE_ONCE(conn->want_flush, 1);
			ret = conn_flush(conn, flags);
			if (ret < 0)
				break;
		}

		if (can_conn_buffer_in(b, data_len)) {
			conn_buffer_in(b, closure->buf + closure->offset,
					data_len);
			closure->state = CLOSURE_STATE_HEADER;
			closure->offset = 0;
			conn->have_pending = 0;
			conn->send_closure = NULL;
			if (conn->waiters)
				pthread_cond_signal(&conn->cond);
			ret = 0;
			break;
		}

		avail = (b->tail - b->head) & b->mask;
		if (avail == 0 && b->full == 0)
			avail = b->size;
		if (avail == 0) {
			ret = -1;
			break;
		}

		if (closure->offset + avail
				> closure->len + conn->have_tail) {
			dprintf(2, "len %d avail %d offset %u is over the buf size %u\n",
					closure->len, avail, closure->offset,
					closure->buf_size);
			abort();
		}

		conn_buffer_in(b, closure->buf + closure->offset, avail);
		closure->offset += avail;
		data_len -= avail;
	} while (data_len > 0);

	if (flags) {
		WRITE_ONCE(conn->want_flush, 1);
		conn_flush(conn, flags);
	}

	pthread_mutex_unlock(&conn->send_mutex);

	return ret;
}

static int conn_send_big_closure(struct xbus_conn *conn,
			struct conn_closure *closure, int flags)
{
	struct iovec iov[2];
	struct msghdr msg;
	struct packet_header header;
	uint32_t data_len;
	int len;
	int ret = 0;

	pthread_mutex_lock(&conn->send_mutex);
	if (conn->have_pending && conn->send_closure != closure) {
		if (flags) {
			conn_wait(conn);
		} else {
			pthread_mutex_unlock(&conn->send_mutex);
			return -1001;
		}
	}

	if (conn_buffer_used(conn->out) > 0) {
		WRITE_ONCE(conn->want_flush, 1);
		ret = conn_flush(conn, flags);
		if (ret != 0) {
			dbg("ret %d\n", ret);
			ret = -1002;
			goto big_out;
		}
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	if (conn->have_tail) {
		data_len = closure->len + 4;
		*((uint32_t *)&closure->buf[closure->len]) = TAIL_MAGIC;
	} else {
		data_len = closure->len;
	}

	if (flags & CONN_NO_PENDING) {
		conn->have_pending = 0;
		conn->send_closure = NULL;
	} else {
		conn->have_pending = 1;
		conn->send_closure = closure;
	}

	msg.msg_iov = iov;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	if (closure->state == CLOSURE_STATE_HEADER) {
		/* send header info first */
		header.id = closure->id;
		header.opt_id1 = closure->opt_id1;
		header.opt_id2 = closure->opt_id2;
		header.size = closure->len;
		header.cmd = closure->cmd;
		header.magic = HEADER_MAGIC;
		memcpy(conn->hdr_buf, &header, sizeof(header));

		len = sizeof(header) - closure->hdr_offset;
		iov[0].iov_base = conn->hdr_buf + closure->hdr_offset;
		iov[0].iov_len = len;
		if (closure->len <= CONN_BUFFER_SIZE) {
			iov[1].iov_base = closure->buf;
			iov[1].iov_len = data_len;
			msg.msg_iovlen = 2;
			len += data_len;
		} else {
			msg.msg_iovlen = 1;
		}

		ret = conn_sendmsg(conn, &msg, flags);
		if (ret < 0)
			goto big_out;
		/* send the part of header */
		if (ret < iov[0].iov_len) {
			closure->hdr_offset += ret;
			ret = -1003;
			goto big_out;
		}

		ret -= sizeof(header);
		closure->state = CLOSURE_STATE_DATA;
		/* send the part of data */
		if (closure->len <= CONN_BUFFER_SIZE) {
			closure->offset += ret;
			if (ret < data_len) {
				ret = -1004;
			} else {
				conn->have_pending = 0;
				conn->send_closure = NULL;
				closure->state = CLOSURE_STATE_HEADER;
				closure->offset = 0;
				ret = 0;
			}
			goto big_out;
		}
	}

	msg.msg_iovlen = 1;
	do {
		iov[0].iov_base = closure->buf + closure->offset;
		if (data_len - closure->offset > 4096)
			iov[0].iov_len = 4096;
		else
			iov[0].iov_len = data_len - closure->offset;
		msg.msg_iov = iov;

		ret = conn_sendmsg(conn, &msg, flags);
		if (ret > 0) {
			closure->offset += ret;
			if (closure->offset != data_len)
				continue;
			break;
		} else {
			break;
		}
	} while (1);

	if (ret >= 0) {
		closure->state = CLOSURE_STATE_HEADER;
		closure->offset = 0;
		conn->have_pending = 0;
		conn->send_closure = NULL;
		if (conn->waiters)
			pthread_cond_signal(&conn->cond);
		ret = 0;
	}

big_out:
	pthread_mutex_unlock(&conn->send_mutex);

	return ret;
}

int conn_send_closure(struct xbus_conn *conn, struct conn_closure *closure,
				int flags)
{
	if (closure->len < CONN_BIG)
		return conn_send_small_closure(conn, closure, flags);
	else
		return conn_send_big_closure(conn, closure, flags);
}

int closure_write(struct conn_closure *closure, const void *buf, size_t size)
{
	int len = size;

	if (len == 0)
		return 0;

	if (size + closure->write_offset > closure->len)
		len = closure->len - closure->write_offset;

	memcpy(closure->buf + closure->write_offset, buf, len);
	closure->write_offset += len;

	return len;
}

int closure_read(struct conn_closure *closure, void *buf, size_t size)
{
	int len = size;

	if (size + closure->read_offset > closure->len)
		len = closure->len - closure->read_offset;

	memcpy(buf, closure->buf + closure->read_offset, len);
	closure->read_offset += len;

	return len;
}

static int idr_iterate_handler(int id, void *p, void *data)
{
	struct closure_zone *zone = p;
	struct conn_closure *closure, *closure1;

	list_for_each_safe(closure, closure1, &zone->all_list, all_entry)
		destroy_closure(closure);

	xfree(zone);

	return 0;
}

int conn_change_fd(struct xbus_conn *conn, int fd)
{
	int nfd;

	pthread_mutex_lock(&conn->mutex);
	conn_buffer_clear(conn->in);
	conn_buffer_clear(conn->out);
	conn_buffer_clear(conn->in_fds);
	conn_buffer_clear(conn->out_fds);
	nfd = os_dupfd_cloexec(fd, 0);
	if (nfd < 0) {
		dprintf(1, "dupfd error %d for changing fd\n", -errno);
		pthread_mutex_unlock(&conn->mutex);
		return -errno;
	}
	close(conn->fd);
	conn->fd = nfd;
	pthread_mutex_unlock(&conn->mutex);

	return 0;
}

void conn_destroy(struct xbus_conn *conn)
{
	pthread_mutex_lock(&conn_mutex);
	list_del(&conn->entry);
	pthread_mutex_unlock(&conn_mutex);
	idr_for_each(&conn->zone_idr, idr_iterate_handler, conn);
	idr_destroy(&conn->zone_idr);
	pthread_mutex_destroy(&conn->mutex);
	pthread_mutex_destroy(&conn->send_mutex);
	if (conn->in)
		destroy_conn_buffer(conn->in);
	if (conn->out)
		destroy_conn_buffer(conn->out);
	if (conn->in_fds)
		destroy_conn_buffer(conn->in_fds);
	if (conn->out_fds)
		destroy_conn_buffer(conn->out_fds);
	close(conn->fd);
	xfree(conn);
}
