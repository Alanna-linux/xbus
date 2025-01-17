#define LOG_TAG 	"IDR"
#define THIS_MODULE 	"IDR"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <idr.h>
#include <log.h>
#include <bitops.h>
#include <error.h>

#define INT_MAX			((~0U) >> 1)

#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_LEVEL 		((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)
#define MAX_IDR_BIT             (1U << MAX_IDR_SHIFT)

static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);

	return (1 << bits) - 1;
}

void idr_init(struct idr *idp)
{
	memset(idp, 0x00, sizeof(struct idr));
	idp->max_free_cnt = 10;
}

struct idr_layer *get_from_free_list(struct idr *layer_idr)
{
	struct idr_layer *idr;

	idr = layer_idr->id_free;
	layer_idr->id_free = idr->ary[0];
	layer_idr->id_free_cnt--;
	memset(idr->bitmap, 0x00, sizeof(idr->bitmap));

	return idr;
}

struct idr_layer *idr_layer_alloc(struct idr *layer_idr)
{
	struct idr_layer *idr;

	if (layer_idr && layer_idr->id_free)
		return get_from_free_list(layer_idr);
	idr = (struct idr_layer *)malloc(sizeof(struct idr_layer));
	layer_idr->mem_size += sizeof(struct idr_layer);
	memset(idr, 0x00, sizeof(struct idr_layer));
	idr->magic = 0xabcd;

	return idr;
}

static void __move_to_free_list(struct idr *idp, struct idr_layer *idr)
{
	if (idp->id_free_cnt > idp->max_free_cnt) {
		idp->mem_size -= sizeof(struct idr_layer);
		free(idr);
		return;
	}
	idr->ary[0] = idp->id_free;
	idp->id_free = idr;
	idp->id_free_cnt++;
}

static int sub_alloc(struct idr *idp, int *starting_id,
			struct idr_layer **pa, struct idr *layer_idr)
{
	int n, m, sh;
	struct idr_layer *p, *new;
	int l, id, oid;

	id = *starting_id;

restart:
	p = idp->top;
	l = idp->layers;
	pa[l--] = NULL;

	for (;;) {
		n = (id >> (IDR_BITS * l)) & IDR_MASK;
		if (p->magic != 0xabcd) {
			printf("magic is not 0xabcd\n");
			abort();
		}
		m = find_next_zero_bit(p->bitmap, IDR_SIZE, n);
		if (m == IDR_SIZE) {
			/* no space available go back to previous layer */
			l++;
			oid = id;
			id = (id | ((1 << (IDR_BITS * l)) - 1)) + 1;
			/* if already at the top layer, we need to grow */
			if (id > idr_max(idp->layers)) {
				*starting_id = id;
				return -EAGAIN;
			}
			p = pa[l];
			check_ptr(p, "layer %d is null\n", l);

			sh = IDR_BITS * (l + 1);
			if (oid >> sh == id >> sh)
				continue;
			else
				goto restart;
		}
		if (m != n) {
			sh = IDR_BITS * l;
			id = ((id >> sh) ^ n ^ m) << sh;
		}
		if ((id >= MAX_IDR_BIT) || id < 0)
			return -ENOSPC;
		if (l == 0)
			break;

		if (!p->ary[m]) {
			new = idr_layer_alloc(layer_idr);
			if (!new)
				return -ENOMEM;
			new->layer = l - 1;
			p->ary[m] = new;
			p->count++;
		}
		pa[l--] = p;
		p = p->ary[m];
	}

	pa[l] = p;
	return id;
}

int idr_get_empty_slot(struct idr *idp, int starting_id,
			struct idr_layer **pa, struct idr *layer_idr)
{
	struct idr_layer *p, *new;
	int layers, id, v;

	id = starting_id;
build_up:
	p = idp->top;
	layers = idp->layers;

	if (!p) {
		p = idr_layer_alloc(layer_idr);
		if (!p) {
			dprintf(1,"failed to alloc idr layer\n");
			return -1;
		}
		p->layer = 0;
		layers = 1;
	}

	while (id > idr_max(layers)) {
		layers++;
		if (!p->count) {
			p->layer++;
			dprintf(1, "the idr tree is empty\n");
			continue;
		}
		new = idr_layer_alloc(layer_idr);
		if (!new) {
			dprintf(1,"failed to alloc idr layer\n");
			for (new = p; p && p != idp->top; new = p) {
				p = new->ary[0];
				new->ary[0] = NULL;
				new->layer = 0;
				new->count = 0;
				memset(new->bitmap, 0, sizeof(new->bitmap));
				__move_to_free_list(idp, new);
			}
			return -1;
		}

		new->ary[0] = p;
		new->count = 1;
		new->layer = layers - 1;
		if (bitmap_full(p->bitmap, IDR_SIZE))
			set_bit(0, new->bitmap);
		p = new;
	}

	idp->top = p;
	idp->layers = layers;
	v = sub_alloc(idp, &id, pa, layer_idr);
	if (v == -EAGAIN)
		goto build_up;

	return(v);
}

static void idr_mark_full(struct idr_layer **pa, int id)
{
	struct idr_layer *p = pa[0];
	int l = 0;

	set_bit(id & IDR_MASK, p->bitmap);

	while (bitmap_full(p->bitmap, IDR_SIZE)) {
		if (!(p = pa[++l]))
			break;
		id = id >> IDR_BITS;
		set_bit((id & IDR_MASK), p->bitmap);
	}
}

static void idr_fill_slot(struct idr *idr, void *ptr, int id,
			struct idr_layer **pa)
{
	idr->hint = pa[0];
	pa[0]->ary[id & IDR_MASK] = (struct idr_layer *)ptr;
	pa[0]->count++;
	idr_mark_full(pa, id);
}

int idr_alloc(struct idr *idp, void *ptr, int start, int end)
{
	int max = end > 0 ? end - 1 : INT_MAX;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	int id;

	if (start < 0 || start > max) {
		dprintf(1,"invalid start id\n");
		return -1;
	}

	id = idr_get_empty_slot(idp, start, pa, idp);
	if (id < 0)
		return id;
	if (id > max)
		return -ENOSPC;

	idr_fill_slot(idp, ptr, id, pa);

	return id;
}

static inline void free_layer(struct idr *idp, struct idr_layer *layer)
{
	__move_to_free_list(idp, layer);
}

static void sub_remove(struct idr *idp, int shift, int id)
{
	struct idr_layer *p = idp->top;
	struct idr_layer **pa[MAX_IDR_LEVEL + 1];
	struct idr_layer ***paa = &pa[0];
	struct idr_layer *to_free;
	int n;

	*paa = NULL;
	*++paa = &idp->top;

	while ((shift > 0) && p) {
		n = (id >> shift) & IDR_MASK;
		clear_bit(n, p->bitmap);
		*++paa = &p->ary[n];
		p = p->ary[n];
		shift -= IDR_BITS;
	}
	n = id & IDR_MASK;
	if (likely(p != NULL && test_bit(n, p->bitmap))) {
		clear_bit(n, p->bitmap);
		p->ary[n] = NULL;
		to_free = NULL;
		while(*paa && ! --((**paa)->count)){
			if (to_free)
				free_layer(idp, to_free);
			to_free = **paa;
			**paa-- = NULL;
		}
		if (!*paa)
			idp->layers = 0;
		if (to_free)
			free_layer(idp, to_free);
	} else
		dprintf(1, "idr_remove called for id=%d "
				"which is not allocated.\n", id);
}

/**
 * idr_remove - remove the given id and free its slot
 * @idp: idr handle
 * @id: unique key
 */
void idr_remove(struct idr *idp, int id)
{
	struct idr_layer *p;
	struct idr_layer *to_free;

	if (id < 0)
		return;

	if (id > idr_max(idp->layers)) {
		dprintf(1, "idr_remove called for id=%d "
				"which is not allocated.\n", id);
		return;
	}

	sub_remove(idp, (idp->layers - 1) * IDR_BITS, id);
	if (idp->top && idp->top->count == 1 && (idp->layers > 1) &&
			idp->top->ary[0]) {
		/*
		 * Single child at leftmost slot: we can shrink the tree.
		 * This level is not needed anymore since when layers are
		 * inserted, they are inserted at the top of the existing
		 * tree.
		 */
		to_free = idp->top;
		p = idp->top->ary[0];
		idp->top = p;
		--idp->layers;
		to_free->count = 0;
		bitmap_zero(to_free->bitmap, IDR_SIZE);
		free_layer(idp, to_free);
	}
}

static void __idr_remove_all(struct idr *idp)
{
	int n, id, max;
	int bt_mask;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	*paa = idp->top;
	idp->top = NULL;
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > IDR_BITS && p) {
			n -= IDR_BITS;
			p = p->ary[(id >> n) & IDR_MASK];
			*++paa = p;
		}

		bt_mask = id;
		id += 1 << n;
		/* Get the highest bit that the above add changed from 0->1. */
		while (n < fls(id ^ bt_mask)) {
			if (*paa)
				free_layer(idp, *paa);
			n += IDR_BITS;
			--paa;
		}
	}
	idp->layers = 0;
}

void idr_destroy(struct idr *idp)
{
	__idr_remove_all(idp);

	while (idp->id_free_cnt) {
		struct idr_layer *p = get_from_free_list(idp);
		free(p);
		idp->mem_size -= sizeof(struct idr_layer);
	}

	dprintf(1, "mem_size: %d\n", idp->mem_size);
}

void *idr_find(struct idr *idp, int id)
{
	int n;
	struct idr_layer *p;

	if (id < 0)
		return NULL;

	p = idp->top;
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;

	if (id > idr_max(p->layer + 1))
		return NULL;

	while (n > 0 && p) {
		n -= IDR_BITS;
		p = p->ary[(id >> n) & IDR_MASK];
	}

	return ((void *)p);
}

/**
 * idr_replace - replace pointer for given id
 * @idp: idr handle
 * @ptr: pointer you want associated with the id
 * @id: lookup key
 *
 * Replace the pointer registered with an id and return the old value.
 * A %-ENOENT return indicates that @id was not found.
 * A %-EINVAL return indicates that @id was not within valid constraints.
 *
 * The caller must serialize with writers.
 */
void *idr_replace(struct idr *idp, void *ptr, int id)
{
	int n;
	struct idr_layer *p, *old_p;

	if (id < 0)
		return ERR_PTR(-EINVAL);

	p = idp->top;
	if (!p)
		return ERR_PTR(-ENOENT);

	if (id > idr_max(p->layer + 1))
		return ERR_PTR(-ENOENT);

	n = p->layer * IDR_BITS;
	while ((n > 0) && p) {
		p = p->ary[(id >> n) & IDR_MASK];
		n -= IDR_BITS;
	}

	n = id & IDR_MASK;
	if (unlikely(p == NULL || !test_bit(n, p->bitmap)))
		return ERR_PTR(-ENOENT);

	old_p = p->ary[n];
	p->ary[n] = ptr;

	return old_p;
}

int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data)
{
	int n, id, max, error = 0;
	struct idr_layer *p;
	struct idr_layer *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];

	n = idp->layers * IDR_BITS;
	*paa = idp->top;
	max = idr_max(idp->layers);

	id = 0;
	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > 0 && p) {
			n -= IDR_BITS;
			p = p->ary[(id >> n) & IDR_MASK];
			*++paa = p;
		}

		if (p) {
			error = fn(id, (void *)p, data);
			if (error)
				break;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			--paa;
		}
	}

	return error;
}
