#ifndef _NOTIFIER_H
#define _NOTIFIER_H

#include <pthread.h>

#define NOTIFY_DONE             0x0000
#define NOTIFY_OK               0x0001
#define NOTIFY_STOP_MASK        0x8000
#define NOTIFY_BAD              (NOTIFY_STOP_MASK|0x0002)

#define BLOCKING_INIT_NOTIFIER_HEAD(name) do {		\
		pthread_mutex_init(&(name)->mutex, NULL);	\
		(name)->head = NULL;			\
	} while (0)

struct blocking_notifier_head {
	pthread_mutex_t mutex;
	struct notifier_block *head;
};

static struct blocking_notifier_head notifier_list;

struct notifier_block;
typedef int notifier_fn_t(struct notifier_block *nb,
		unsigned long action, void *data);

struct notifier_block {
	notifier_fn_t *notifier_call;
	struct notifier_block *next;
	int priority;
	void *priv;
};

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
		unsigned long val, void *v);
int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
		struct notifier_block *n);
int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n);
int nonblocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n);

static inline void notifier_set_private(struct notifier_block *nb, void *priv)
{
	nb->priv = priv;
}

static inline void *notifier_get_private(struct notifier_block *nb)
{
	return nb->priv;
}

static inline int notifier_call_chain(unsigned long val, void *v)
{
	return blocking_notifier_call_chain(&notifier_list, val, v);
}

static inline int register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&notifier_list, nb);
}

static inline int unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&notifier_list, nb);
}

static inline int nonblocking_unregister_notifier(struct notifier_block *nb)
{
	return nonblocking_notifier_chain_unregister(&notifier_list, nb);
}

static inline void notifier_head_init()
{
	BLOCKING_INIT_NOTIFIER_HEAD(&notifier_list);
}

#endif
