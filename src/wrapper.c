/**
 *   Copyright (C) 2021 All rights reserved.
 *
 *   FileName      ：wrapper.c
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2021-07-08
 *   Description   ：
 */

#define LOG_TAG 	"WRAPPER"
#define LOG_LEVEL 3

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <log.h>
#include <utils.h>
#include <idr.h>
#include <bitops.h>
#include <uapi/xbus.h>
#include "xbus-protocol.h"

#define MEM_INFO_STATE_END		1
struct mem_info {
	char				tag[MAX_NAME_LEN];
	uint8_t				state;
	int32_t				size;
};

struct memory_object {
	int			index;
	size_t			size;
	char			mem[0];
};

struct memory_zone {
	struct list_head 	entry;
	char 			tag[64];
	int 			id;
	int64_t 		size;
};

struct memory_class {
	struct list_head 	zone_list;
	int 			zone_cnt;
	int			zone_index;
	struct idr 		zone_idr;
	pthread_mutex_t 	mutex;
	int32_t			alloced_size;
	int32_t			obj_cnt;
};

static struct memory_class *mem_class = NULL;

static struct memory_class *get_memory_class()
{
	return mem_class;
}

static void memory_class_lock(struct memory_class *mc)
{
	pthread_mutex_lock(&mc->mutex);
}

static void memory_class_unlock(struct memory_class *mc)
{
	pthread_mutex_unlock(&mc->mutex);
}

void *xmalloc_common(size_t size)
{
	struct memory_class *mc;
	struct memory_object *mb;

	mc = get_memory_class();
	check_ptr(mc, "robot memory block has not been initialized yet\n");

	mb = (struct memory_object *)malloc(sizeof(struct memory_object) + size);
	if (mb == NULL)
		return NULL;

	mb->index = mc->obj_cnt++;
	mb->size = size;
	memory_class_lock(mc);
	mc->alloced_size += size;
	dprintf(4, "alloc memory: %lu bytes, allocated memory: %d bytes\n",
			mb->size, mc->alloced_size);
	memory_class_unlock(mc);

	return mb->mem;
}

void *xzmalloc_common(size_t size)
{
	void *p;

	p = xmalloc_common(size);
	if (p != NULL)
		memset(p, 0x00, size);

	return p;
}

void xfree_common(void *ptr)
{
	struct memory_class *mc;
	struct memory_object *mb;
	char *mem = (char *)ptr;

	mc = get_memory_class();
	check_ptr(mc, "robot memory block has not been initialized yet\n");

	mb = container_of(mem, mb, mem);

	memory_class_lock(mc);
	mc->alloced_size -= mb->size;
	dprintf(4, "free memory: %lu bytes, allocated memory: %d bytes\n",
			mb->size, mc->alloced_size);
	memory_class_unlock(mc);

	free(mb);
}

void *xrealloc_common(void *old_ptr, size_t size)
{
	struct memory_class *mc;
	struct memory_object *mb;

	if (old_ptr == NULL)
		return xmalloc_common(size);

	mc = get_memory_class();
	check_ptr(mc, "memory block has not been initialized yet\n");

	mb = container_of((char *)old_ptr, mb, mem);

	mb = realloc(mb, sizeof(struct memory_object) + size);
	if (mb == NULL)
		return NULL;

	memory_class_lock(mc);
	mc->alloced_size += size - mb->size;
	mb->size = size;
	dprintf(4, "realloc memory: %lu bytes, allocated memory: %d bytes\n",
			mb->size, mc->alloced_size);
	memory_class_unlock(mc);

	return mb->mem;
}

static struct memory_zone *mem_zone_create(void)
{
	struct memory_zone *zone;

	zone = (struct memory_zone *)malloc(sizeof(struct memory_zone));
	check_ptr(zone, "No memory for memory zone\n");

	INIT_LIST_HEAD(&zone->entry);
	zone->size = 0;
	zone->id = 0;

	return zone;
}

static struct memory_zone *mem_find_zone(struct memory_class *mc,
		const char *tag)
{
	struct memory_zone *zone;
	int found = 0;

	list_for_each_entry(zone, &mc->zone_list, entry) {
		if (!strncmp(zone->tag, tag, sizeof(zone->tag))) {
			found = 1;
			break;
		}
	}

	return found ? zone : NULL;
}

static void mem_print_zone_info(struct memory_class *mc)
{
	struct memory_zone *zone;

	dprintf(1, "EACH MODULE MEMORY INFO:\n");
	list_for_each_entry(zone, &mc->zone_list, entry)
		dprintf(1, "\tMODULE %s: %lld\n", zone->tag, zone->size);
}

static struct memory_zone *alloc_memory_zone(struct memory_class *mc,
				const char *tag, int id)
{
	struct memory_zone *zone;
	int ret;

	switch (id) {
	case -1:
		zone = mem_find_zone(mc, tag);
		if (zone)
			break;

		zone = mem_zone_create();
		ret = idr_alloc(&mc->zone_idr, zone, 0, 0);
		if (ret < 0) {
			dprintf(1, "idr alloc error for mem zone\n");
			abort();
		}

		zone->id = ret;
		strncpy(zone->tag, tag, sizeof(zone->tag));
		list_add(&zone->entry, &mc->zone_list);
		mc->zone_cnt++;
		break;
	default:
		zone = idr_find(&mc->zone_idr, id);
		check_ptr(zone, "invalid id %d to find zone\n", id);
		break;
	}

	return zone;
}

void *xmalloc_dbg(const char *tag, int *id, size_t size)
{
	struct memory_class *mc;
	struct memory_zone *zone;
	void *p;

	mc = get_memory_class();

	p = xmalloc_common(size);
	if (p == NULL)
		return NULL;

	memory_class_lock(mc);

	zone = alloc_memory_zone(mc, tag, *id);
	if (*id < 0)
		*id = zone->id;
	zone->size += size;
	dprintf(4, "mem zone %s size: %lld, +size: %lld\n",
			zone->tag, zone->size, size);
	memory_class_unlock(mc);

	return p;
}

void *xzmalloc_dbg(const char *tag, int *id, size_t size)
{
	struct memory_class *mc;
	struct memory_zone *zone;
	void *p;

	mc = get_memory_class();

	p = xzmalloc_common(size);
	if (p == NULL)
		return NULL;

	memory_class_lock(mc);

	zone = alloc_memory_zone(mc, tag, *id);
	if (*id < 0)
		*id = zone->id;
	zone->size += size;
	dprintf(4, "mem zone %s size: %lld, +size: %lld\n",
			zone->tag, zone->size, size);
	memory_class_unlock(mc);

	return p;
}

void *xrealloc_dbg(const char *tag, int *id, void *old_ptr, size_t size)
{
	struct memory_class *mc;
	struct memory_zone *zone;
	struct memory_object *mb;
	size_t old_size = 0;
	void *p;

	if (old_ptr) {
		mb = container_of((char *)old_ptr, mb, mem);
		old_size = mb->size;
	}

	p = xrealloc_common(old_ptr, size);
	if (p == NULL)
		return NULL;

	mc = get_memory_class();

	memory_class_lock(mc);
	zone = alloc_memory_zone(mc, tag, *id);
	if (*id < 0)
		*id = zone->id;
	zone->size += size - old_size;
	dprintf(4, "mem zone %s size: %lld\n", zone->tag, zone->size);
	memory_class_unlock(mc);

	return p;
}

void xfree_dbg(const char *tag, int *id, void *p)
{
	struct memory_class *mc;
	struct memory_object *mb;
	struct memory_zone *zone;
	char *mem = (char *)p;

	mc = get_memory_class();

	memory_class_lock(mc);
	if (*id == -1) {
		dprintf(1, "invalid id for xfree\n");
		memory_class_unlock(mc);
		return;
	}

	zone = idr_find(&mc->zone_idr, *id);
	check_ptr(zone, "idr find error in zone_idr\n");
	mb = container_of(mem, mb, mem);
	zone->size -= mb->size;
	dprintf(4, "mem zone %s size: %lld, -size: %lld\n",
			zone->tag, zone->size, mb->size);
	memory_class_unlock(mc);

	xfree_common(p);
}

int mem_init()
{
	int ret;

	if (mem_class) {
		dprintf(1, "mem is already initialized\n");
		return 0;
	}

	mem_class = (struct memory_class *)malloc(sizeof(struct memory_class));
	check_ptr(mem_class, "cannot alloc memory class struct\n");
	ret = pthread_mutex_init(&mem_class->mutex, NULL);
	if (ret != 0) {
		dprintf(1, "cannot init mem mutex\n");
		return -1;
	}

	idr_init(&mem_class->zone_idr);
	INIT_LIST_HEAD(&mem_class->zone_list);

	mem_class->alloced_size = 0;
	mem_class->obj_cnt = 0;

	return 0;
}

static int mem_dbg_service(struct xbus_request *req, void *p)
{
	struct memory_class *mc = p;
	struct memory_zone *zone;
	struct mem_info *minfo = req->resp;

	memory_class_lock(mc);

	zone = idr_find(&mc->zone_idr, mc->zone_index);
	if (zone) {
		strncpy(minfo->tag, zone->tag, sizeof(minfo->tag));
		minfo->size = zone->size;
		mc->zone_index++;
	} else {
		minfo->state = MEM_INFO_STATE_END;
		mc->zone_index = 0;
	}

	memory_class_unlock(mc);

	return 0;
}

void mem_register_service(const char *prefix, int id)
{
	struct memory_class *mc;
	char name[32] = {0};

	mc = get_memory_class();
	if (!mc) {
		dprintf(1, "memory_class does not exist\n");
		return;
	}

	if (prefix && id >= 0)
		snprintf(name, sizeof(name), "srv_%s%d_mem", prefix, id);
	else if (prefix)
		snprintf(name, sizeof(name), "srv_%s_mem", prefix);
	else
		snprintf(name, sizeof(name), "srv_%d_mem", id);

	dprintf(1, "mem service name %s\n", name);
	xbus_service(name, mem_dbg_service, mc);
}

void mem_close(void)
{
	struct memory_class *mc;

	mc = get_memory_class();
	if (!mc) {
		dprintf(1, "memory_class does not exist\n");
		return;
	}

	mem_print_zone_info(mc);

	dprintf(1, "allocated_size: %d\n", mc->alloced_size);
	if (mc->alloced_size > 0) {
		dprintf(1, "allocate size is not zero,"
				"maybe somewher has not release yet\n");
		return;
	}

	pthread_mutex_destroy(&mc->mutex);

	free(mc);
	mem_class = NULL;
}

/**
 * strdup2 - same as strdup but memory allocs
 * @str: the string duplicated
 *
 * returns a new string buffer on success, or null on errors.
 */
void *xstrdup_dbg(const char *tag, int *id, const char *str)
{
	char *p;
	int len;

	if (!str)
		return NULL;

	len = strlen(str);
	if (len == 0)
		return NULL;

	p = (char *)xmalloc_dbg(tag, id, len + 1);
	if (p == NULL)
		return NULL;

	memset(p, 0, len + 1);
	strncpy(p, str, len);

	return p;
}

void *xstrdup_common(const char *str)
{
	char *p;
	int len;

	if (!str)
		return NULL;

	len = strlen(str);
	if (len == 0)
		return NULL;

	p = (char *)xmalloc_common(len + 1);
	if (p == NULL)
		return NULL;

	strncpy(p, str, len);
	p[len] = '\0';

	return p;
}
