/**
 * xbus-protocol.h
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#ifndef _XBUS_PROTOCOL_H
#define _XBUS_PROTOCOL_H

#include <stdint.h>

#define MAX_NAME_LEN			64

/* master side */
#define XBUS_CMD_PUB_TOPIC		0
#define XBUS_CMD_SUB_TOPIC		1
#define XBUS_CMD_TCP_PORT		2
#define XBUS_CMD_NEW_SVC		3
#define XBUS_CMD_NEW_REQ		4
#define XBUS_CMD_GET_PUB		5
#define XBUS_CMD_GET_SUB		6
#define XBUS_CMD_NODE_NAME		7
#define XBUS_CMD_LIST_NODE		8
#define XBUS_CMD_UNSUB_TOPIC		9
#define XBUS_CMD_NEW_PUB_NTF 		10

/* node side */
#define NODE_CMD_DISTRIBUTE_ID 		0
#define NODE_CMD_TOPIC_ID		1
#define NODE_CMD_UNIX_LINK		2
#define NODE_CMD_NEW_EVENT		3
#define NODE_CMD_REQ_PORT		4
#define NODE_CMD_TCP_LINK		5
#define NODE_CMD_SVC_ID			6
#define NODE_CMD_PUB_INFO		7
#define NODE_CMD_SUB_INFO		8
#define NODE_CMD_NODE_INFO		9
#define NODE_CMD_END			10
#define NODE_CMD_NEW_PUB_NTF		11

/* proxy node side */

/* bind node side */

/* proxy and bind node shared cmd */
#define BP_CMD_SUBSCRIBE		0
#define BP_CMD_MSG			1
#define BP_CMD_NEW_SRV			2
#define BP_CMD_REQUEST			3
#define BP_CMD_REQ_ACK			4
#define BP_CMD_NEW_SHM			5
#define BP_CMD_FREE_SHM_BUF		6
#define BP_CMD_UNSUBCRIBE		7
#define BP_CMD_LINK			8

struct xbus_info {
	char				name[MAX_NAME_LEN];
	char				topic[MAX_NAME_LEN];
	int32_t				xbusid;
	int32_t				id;
	uint16_t			port;
	uint8_t				issvc;
	char				buf[64];
};

struct report_info {
	char 				topic[MAX_NAME_LEN];
	uint8_t				count;
};

struct shm_info {
	int32_t				per_size;
	int32_t				count;
};

#endif
