#ifndef _IDR_H
#define _IDR_H

#include "bitops.h"

#define IDR_BITS 		4
#define IDR_SIZE 		(1 << IDR_BITS)
#define IDR_MASK 		((1 << IDR_BITS) - 1)

struct idr_layer {
	int			prefix;
	int			layer;
	struct idr_layer	*ary[1 << IDR_BITS];
	int			count;
	DECLARE_BITMAP(bitmap, IDR_SIZE);
	int 			magic;
};

struct idr {
	struct idr_layer	*hint;
	struct idr_layer	*top;
	int			layers;
	int			id_free_cnt;
	int 			max_free_cnt;
	int 			mem_size;
	struct idr_layer	*id_free;
};

int idr_alloc(struct idr *idp, void *ptr, int start, int end);
void *idr_find(struct idr *idp, int id);
void *idr_replace(struct idr *idp, void *ptr, int id);
void idr_init(struct idr *idp);
void idr_destroy(struct idr *idp);
void idr_remove(struct idr *idp, int id);
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data);

#endif
