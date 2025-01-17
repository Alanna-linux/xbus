/**
	> File Name: xbus-conn.h
	> Author: zhujiongfu
	> Mail: zhujiongfu@live.cn 
	> Created Time: Sat 09 Jun 2018 04:17:11 PM CST
 */

#ifndef _XBUS_CONN_H
#define _XBUS_CONN_H

#include <stdint.h>
#include <sys/socket.h>
#include <pthread.h>

#include <utils.h>
#include <idr.h>

#define CONN_NO_PENDING		(1 << 1)
enum closure_state {
	CLOSURE_STATE_HEADER,
	CLOSURE_STATE_DATA,
};

struct conn_closure {
	struct list_head	entry;
	struct list_head	all_entry;
	int			fds[8];
	int			fds_len;
	int32_t			id;
	int32_t 		opt_id1;
	int32_t 		opt_id2;
	int32_t			cmd;
	uint32_t		offset;
	uint32_t		len;
	uint32_t		buf_size;
	uint32_t		write_offset;
	uint32_t		read_offset;
	enum closure_state 	state;
	int8_t			refcnt;
	uint8_t 		hdr_offset;
	char 			*buf;
};

enum conn_decode_stage {
	CONN_DECODE_HEADER,
	CONN_DECODE_DATA,
	CONN_DECODE_DATA_BIG,
	CONN_DECODE_DATA_END,
};

struct conn_buffer {
	uint16_t 		head;
	uint16_t 		tail;
	uint32_t 		size;
	uint32_t 		mask;
	uint8_t 		full;
	uint8_t 		*data;
};

struct xbus_conn {
	struct conn_buffer 	*in;
	struct conn_buffer 	*out;
	struct conn_buffer 	*in_fds;
	struct conn_buffer 	*out_fds;
	struct idr		zone_idr;
	struct list_head 	entry;
	struct conn_closure	*recv_closure;
	struct conn_closure	*send_closure;
	enum conn_decode_stage	stage;
	pthread_mutex_t 	mutex;
	pthread_mutex_t 	send_mutex;
	pthread_cond_t		cond;
	int			refcnt;
	int			fd;
	int			have_tail;
	uint8_t 		want_flush;
	uint8_t 		have_pending;
	uint8_t 		waiters;
	char	 		*hdr_buf;
};

struct xbus_conn *conn_create(int fd, int have_tail);
int conn_change_fd(struct xbus_conn *conn, int fd);
void conn_destroy(struct xbus_conn *conn);
void conn_put(struct xbus_conn *conn);
void conn_get(struct xbus_conn *conn);
int conn_read(struct xbus_conn *conn);
struct conn_closure *conn_alloc_closure(struct xbus_conn *conn,
		int32_t id, size_t size);
void conn_free_closure(struct xbus_conn *conn, struct conn_closure *closure);
struct conn_closure *conn_decode_closure(struct xbus_conn *conn);
int conn_send_closure(struct xbus_conn *conn, struct conn_closure *closure,
				int block);
void conn_flush_all(void);
void conn_closure_ref(struct xbus_conn *conn, struct conn_closure *closure);
int closure_write(struct conn_closure *closure, const void *buf, size_t size);
int closure_read(struct conn_closure *closure, void *buf, size_t size);

static inline void *closure_data(struct conn_closure *closure)
{
	return closure->buf + closure->read_offset;
}

#endif
