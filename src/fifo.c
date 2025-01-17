/**
 *   Copyright (C) 2019 All rights reserved.
 *
 *   FileName      ：fifo.c
 *   Author        ：zhujiongfu
 *   Email         ：zhujiongfu@live.cn
 *   Date          ：2019-09-02
 *   Description   ：
 */

#define THIS_MODULE 	"FIFO"

#include <stdio.h>
#include <string.h>

#include <wrapper.h>
#include <fifo.h>
#include <log.h>
#include <bitops.h>
#include <log2.h>

#define is_power_of_2(x)                        ((x) != 0 && (((x) & ((x) - 1)) == 0))

int fifo_init(struct fifo *fifo, size_t size)
{
	size = roundup_pow_of_two(size);

	fifo->data = xmalloc(size);
	if (fifo->data == NULL) {
		dprintf(1, "No memory for fifo\n");
		return -1;
	}

	fifo->in = 0;
	fifo->out = 0;
	fifo->mask = size - 1;

	return 0;
}

void fifo_release(struct fifo *fifo)
{
	xfree(fifo->data);
}

unsigned int fifo_unused(struct fifo *fifo)
{
	return (fifo->mask + 1) - (fifo->in - fifo->out);
}

static void fifo_copy_in(struct fifo *fifo, const void *buf, int len)
{
	unsigned int l;
	unsigned int off = fifo->in;
	unsigned int size = fifo->mask + 1;

	off &= fifo->mask;

	l = min(len, (int)(size - off));

	memcpy((fifo->data + off), buf, l);
	memcpy(fifo->data, buf + l, (len - l));
}

unsigned int fifo_in(struct fifo *fifo,
			const void *buf, unsigned int len)
{
	unsigned int l;

	l = fifo_unused(fifo);
	if (l < len)
		len = l;

	fifo_copy_in(fifo, buf, len);
	fifo->in += len;

	return len;
}

static void fifo_copy_out(struct fifo *fifo,
				void *dst, unsigned int len)
{
	unsigned int l;
	unsigned int size = fifo->mask + 1;
	unsigned int off = fifo->out;

	off &= fifo->mask;

	l = min(len, (size - off));
	memcpy(dst, fifo->data + off, l);
	memcpy(dst + l, fifo->data, len - l);
}

unsigned int fifo_out(struct fifo *fifo, void *dst, unsigned int len)
{
	unsigned int l;

	l = fifo->in - fifo->out;
	if (l < len)
		len = l;

	fifo_copy_out(fifo, dst, len);
	fifo->out += len;

	return len;
}

void *fifo_prefetch(struct fifo *fifo, unsigned int *rlen)
{
	unsigned int len;
	unsigned int size = fifo->mask + 1;
	unsigned int off = fifo->out;

	len = fifo->in - fifo->out;
	if (len == 0)
		return NULL;

	off &= fifo->mask;

	*rlen = min(len, (size - off));

	return fifo->data + off;
}
