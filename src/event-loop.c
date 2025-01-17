#define THIS_MODULE 	"ELOOP"
#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <event-loop.h>
#include <log.h>
#include <wrapper.h>
#include <os.h>
#include <error.h>

struct event_source_fd {
	struct event_source base;
	event_loop_fd_func_t *func;
	int fd;
};

struct event_source_signal {
	struct event_source base;
	int signal_number;
	event_loop_signal_func_t *func;
};

int epoll_create_cloexec(void)
{
	int fd;

	fd = epoll_create(1);

	return set_cloexec_or_close(fd);
}

struct event_loop *event_loop_create(void)
{
	struct event_loop *loop;

	loop = xmalloc(sizeof(*loop));
	if (loop == NULL) {
		dprintf(1, "NO memory for creating event_loop!!\n");
		return ERR_PTR(-EHAL_NOMEM);
	}

	loop->epoll_fd = epoll_create_cloexec();
	if (loop->epoll_fd < 0) {
		xfree(loop);
		return ERR_PTR(-EHAL_INVAL);
	}
	INIT_LIST_HEAD(&loop->destroy_list);

	return loop;
}

int event_loop_dispatch(struct event_loop *loop, int timeout)
{
	struct epoll_event ep[32];
	struct event_source *source, *tsource;
	int count, i, ret = 0;

	count = epoll_wait(loop->epoll_fd, ep, ARRAY_SIZE(ep), timeout);
	if (count < 0) {
		if (errno == EINTR)
			return 0;
		perror("epoll_wait error");
		return -1;
	}

	for (i = 0; i < count; i++) {
		source = ep[i].data.ptr;
		if (source->fd == -1)
			continue;
		ret = source->interface->dispatch(source, &ep[i]);
		if (ret < 0)
			break;
	}

	list_for_each_safe(source, tsource, &loop->destroy_list, link) {
		list_del(&source->link);
		xfree(source);
	}
	INIT_LIST_HEAD(&loop->destroy_list);

	return ret;
}

void event_loop_destroy(struct event_loop *loop)
{
	close(loop->epoll_fd);
	xfree(loop);
}

struct event_source *add_source(struct event_loop *loop,
				struct event_source *source, uint32_t mask,
				void *data)
{
	struct epoll_event ep;

	source->data = data;
	source->loop = loop;
	INIT_LIST_HEAD(&source->link);

	memset(&ep, 0, sizeof(ep));

	if (mask & EVENT_READABLE)
		ep.events |= EPOLLIN;
	if (mask & EVENT_WRITABLE)
		ep.events |= EPOLLOUT;
	if (mask & EVENT_ET)
		ep.events |= EPOLLET;
	if (mask & EVENT_ONESHOT)
		ep.events |= EPOLLONESHOT;
	ep.data.ptr = source;

	if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, source->fd, &ep) < 0) {
		close(source->fd);
		xfree(source);
		return NULL;
	}

	return source;
}

static int fd_event_dispatch(struct event_source *source,
				struct epoll_event *ep)
{
	struct event_source_fd *fd_source =
				(struct event_source_fd *)source;
	uint32_t mask = 0;

	if (ep->events & EPOLLIN)
		mask |= EVENT_READABLE;
	if (ep->events & EPOLLOUT)
		mask |= EVENT_WRITABLE;
	if (ep->events & EPOLLHUP)
		mask |= EVENT_HANGUP;
	if (ep->events & EPOLLERR)
		mask |= EVENT_ERROR;
	/*printf("mask: 0x%x\n", mask);*/

	return fd_source->func(fd_source->fd, mask, source->data);
}

struct event_source_interface fd_event_source_interface = {
	.dispatch = &fd_event_dispatch,
};

struct event_source *event_loop_add_fd(struct event_loop *loop,
				int fd, uint32_t mask,
				event_loop_fd_func_t *func,
				void *data)
{
	struct event_source_fd *source;

	source = xmalloc(sizeof(*source));
	if (source == NULL) {
		dprintf(1, "failed to malloc fd source\n");
		return NULL;
	}

	source->base.interface = &fd_event_source_interface;
	source->base.fd = os_dupfd_cloexec(fd, 0);
	if (source->base.fd < 0) {
		dprintf(1, "dup fd err\n");
		xfree(source);
		return NULL;
	}
	source->func = func;
	source->fd = fd;

	return add_source(loop, &source->base, mask, data);
}

int event_source_fd_update(struct event_source *source, uint32_t mask)
{
	struct event_loop *loop = source->loop;
	struct epoll_event ep;

	memset(&ep, 0, sizeof ep);
	if (mask & EVENT_READABLE)
		ep.events |= EPOLLIN;
	if (mask & EVENT_WRITABLE)
		ep.events |= EPOLLOUT;
	if (mask & EVENT_ONESHOT)
		ep.events |= EPOLLONESHOT;
	ep.data.ptr = source;

	return epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, source->fd, &ep);
}

static int event_source_signal_dispatch(struct event_source *source,
					struct epoll_event *ep)
{
	struct event_source_signal *signal_source =
		(struct event_source_signal *)source;
	struct signalfd_siginfo signal_info;
	int len;

	len = read(source->fd, &signal_info, sizeof(struct signalfd_siginfo));
	if (!(len == -1 && errno == EAGAIN)
			&& len != sizeof(struct signalfd_siginfo))
		dprintf(1, "signalfd read error: %m\n");

	return signal_source->func(signal_source->signal_number,
			signal_source->base.data);
}

static struct event_source_interface signal_source_interface = {
	event_source_signal_dispatch,
};

struct event_source *event_loop_add_signal(struct event_loop *loop,
			int signal_number,
			event_loop_signal_func_t *func, void *data)
{
	struct event_source_signal *source;
	sigset_t mask;

	source = xmalloc(sizeof(struct event_source_signal));
	if (source == NULL)
		return NULL;

	source->base.interface = &signal_source_interface;
	source->signal_number = signal_number;

	sigemptyset(&mask);
	sigaddset(&mask, signal_number);
	source->base.fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	source->func = func;

	return add_source(loop, &source->base, EVENT_READABLE, data);
}

void event_source_remove(struct event_source *source)
{
	struct event_loop *loop = source->loop;

	if (source->fd > 0) {
		epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, source->fd, NULL);
		close(source->fd);
		source->fd = -1;
	}

	list_add(&source->link, &loop->destroy_list);
}
