/**
 *   Copyright (C) 2020 All rights reserved.
 *
 *   FileName      : xbus.h
 *   Author        : zhujiongfu
 *   Email         : zhujiongfu@live.cn
 *   Date          : 2020-08-23
 *   Description   :
 */

#ifndef _UAPI_XBUS_H
#define _UAPI_XBUS_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XBUS_MASTER_PORT 	2222

#define G_BLOCK			(1UL << 1)

struct xbus_shm_pool {
	int			fd;
	int32_t			id;
	size_t			per_size;
	size_t			align_size;
	int8_t			count;
	unsigned char		*data;
};

struct xbus_shm_buf {
	int32_t			offset;
	size_t			size;
	uint8_t			index;
	void			*data;
};

struct xbus_pub {
	char 			topic[32];
	struct xbus_shm_pool *pool;
	int32_t 		id;
	int32_t			flag;
	int			max_queue_len;
};

struct xbus_request {
	char			service[32];
	int32_t			reqid;
	int32_t			req_len;
	int32_t			resp_len;
	void			*req;
	void			*resp;
};

enum xbus_event {
	XBUS_EVENT_NONE,
	XBUS_EVENT_NODE_ONLINE,
	XBUS_EVENT_NODE_OFFLINE,
	XBUS_EVENT_SUB_ONLINE,
	XBUS_EVENT_SUB_OFFLINE,
	XBUS_EVENT_PUB_ONLINE,
	XBUS_EVENT_PUB_OFFLINE,
	XBUS_EVENT_NEW_PUB,
};

struct xbus_notification {
	enum xbus_event ev;
	union {
		char *name;
	};
};

typedef void xbus_ntf_func_t(struct xbus_notification *ntf, void *data);
struct xbus_notifier {
	int8_t priority;
	xbus_ntf_func_t *func;
	void *data;
};

typedef void user_cmd_func_t(int cmd, void *data, void *p);

/* xbus master api */
int xbus_init_s(void);
void xbus_run_s();

/* xbus client api */
typedef int subscribe_func_t(void *data, int len, void *p);
typedef int service_func_t(struct xbus_request *req, void *p);

int xbus_init(const char *name, int max_threads);
void xbus_log(const char *fmt, ...);
void xbus_spin(void);
int xbus_register_notifier(struct xbus_notifier *ntf);
void xbus_unregister_notifier(struct xbus_notifier *ntf);
int xbus_service(const char *service, service_func_t *func, void *data);
int xbus_request_init(const char *service, struct xbus_request *req);
int xbus_request(struct xbus_request *req);
int xbus_pub_init(struct xbus_pub *pub,
			const char *topic, int queue_len);
int xbus_pub_create_shm(struct xbus_pub *pub, int size, int count);
struct xbus_shm_buf *xbus_pub_get_shmbuf(struct xbus_pub *pub, uint32_t flag);
int xbus_subscribe(const char *topic, int queue_len,
			subscribe_func_t *func, void *data);
int xbus_unsubscribe(int id);
int xbus_publish(struct xbus_pub *pub, const void *data, size_t len);

/* Advanced APIs */
int xbus_register_cmd(user_cmd_func_t *func, void *data);
int xbus_send_cmd(int cmd, void *data, int len);

#ifdef __cplusplus
}
#endif

#endif
