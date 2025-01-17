/**
 *	> File Name: video_notifier.c
 *	> Created Time: 23 Sep 2021 08:26:04 PM CST
 */

#include<stdio.h>

#include <notifier.h>

static int notifier_chain_register(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	*nl = n;
	return 0;
}

int notifier_chain_unregister(struct notifier_block **nl,
		struct notifier_block *n)
{
	while ((*nl) != NULL) {
		if ((*nl) == n) {
			*nl = n->next;
			return 0;
		}
		nl = &((*nl)->next);
	}
	return -1;
}

/**
 *	blocking_notifier_chain_register - Add notifier to a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: New entry in the notifier chain
 *
 *	Adds a notifier to a blocking notifier chain.
 *	Must be called in process context.
 *
 *	Currently always returns zero.
 */
int blocking_notifier_chain_register(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	pthread_mutex_lock(&nh->mutex);
	ret = notifier_chain_register(&nh->head, n);
	pthread_mutex_unlock(&nh->mutex);
	return ret;
}

/**
 *	blocking_notifier_chain_unregister - Remove notifier from a blocking notifier chain
 *	@nh: Pointer to head of the blocking notifier chain
 *	@n: Entry to remove from notifier chain
 *
 *	Remove a notifier from a blocking notifier chain.
 *	Must be called from process context.
 *
 *	Returns zero on success or -1 on failure.
 */
int blocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	pthread_mutex_lock(&nh->mutex);
	ret = notifier_chain_unregister(&nh->head, n);
	pthread_mutex_unlock(&nh->mutex);
	return ret;
}

int nonblocking_notifier_chain_unregister(struct blocking_notifier_head *nh,
		struct notifier_block *n)
{
	int ret;

	ret = notifier_chain_unregister(&nh->head, n);
	return ret;
}

static int __notifier_call_chain(struct notifier_block **nl,
				unsigned long val, void *v,
				int nr_to_call, int *nr_calls)
{
	int ret = 0;
	struct notifier_block *nb, *next_nb;

	nb = *nl;

	while (nb && nr_to_call) {
		next_nb = nb->next;

		ret = nb->notifier_call(nb, val, v);

		if (nr_calls)
			(*nr_calls)++;
		if ((ret & NOTIFY_STOP_MASK) == NOTIFY_STOP_MASK)
			break;
		nb = next_nb;
		nr_to_call--;
	}
	return ret;
}

static int __blocking_notifier_call_chain(struct blocking_notifier_head *nh,
					unsigned long val, void *v,
					int nr_to_call, int *nr_calls)
{
	int ret = 0;

	pthread_mutex_lock(&nh->mutex);
	ret = __notifier_call_chain(&nh->head, val, v, nr_to_call, nr_calls);
	pthread_mutex_unlock(&nh->mutex);
	return ret;
}

int blocking_notifier_call_chain(struct blocking_notifier_head *nh,
		unsigned long val, void *v)
{
	return __blocking_notifier_call_chain(nh, val, v, -1, NULL);
}
