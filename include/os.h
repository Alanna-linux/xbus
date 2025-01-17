/**
 *	> File Name: manager-os.h
 *	> Author: zhujiongfu
 *	> Mail: zhujiongfu@live.cn 
 */

#ifndef	_OS_H
#define	_OS_H

#include <sys/socket.h>

struct dt_spec {
	struct timespec sts;
	struct timespec ets;
};

void dt_spec_start(struct dt_spec *ds);
void dt_spec_end(struct dt_spec *ds, int limit, const char *prefix);
ssize_t os_recvmsg_cloexec(int sockfd, struct msghdr *msg, int flags);
int os_dupfd_cloexec(int fd, long minfd);
int os_accept_cloexec(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int os_socket_cloexec(int domain, int type, int protocol);
int set_cloexec_or_close(int fd);
int get_iface_name(char *iface_name, int len);
int get_local_ip(const char *eth_inf, char *ip);
int mkdir_r(const char *path, mode_t mode);

#endif
