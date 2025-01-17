#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include<time.h>

#include <log.h>
#include <os.h>

void dt_spec_start(struct dt_spec *ds)
{
	clock_gettime(CLOCK_MONOTONIC, &ds->sts);
}

void dt_spec_end(struct dt_spec *ds, int limit, const char *prefix)
{
	double dt;

	clock_gettime(CLOCK_MONOTONIC, &ds->ets);
	dt = (ds->ets.tv_sec - ds->sts.tv_sec) * 1000.0;
	dt += (ds->ets.tv_nsec - ds->sts.tv_nsec) / 1000000.0;

	if (limit == 0 || dt > limit) {
		dprintf(3, "%s cost time %lf(ms)\n",
				prefix ? prefix : "NULL", dt);
	}
	ds->sts = ds->ets;
}

int set_cloexec_or_close(int fd)
{
	long flags;

	if (fd == -1) {
		dprintf(1,"invalid fd value\n");
		return -1;
	}

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		goto err;

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
		goto err;

	return fd;

err:
	dprintf(1,"set cloexe error\n");
	close(fd);
	return -1;
}

int os_dupfd_cloexec(int fd, long minfd)
{
	int newfd;

	newfd = fcntl(fd, F_DUPFD_CLOEXEC, minfd);
	if (newfd >= 0)
		return newfd;

	if (errno != EINVAL)
		return -1;

	newfd = fcntl(fd, F_DUPFD, minfd);
	return set_cloexec_or_close(newfd);
}

int os_socket_cloexec(int domain, int type, int protocol)
{
	int fd;

	fd = socket(domain, type | SOCK_CLOEXEC, protocol);
	if (fd >= 0)
		return fd;

	if (errno != EINVAL)
		return -1;

	fd = socket(domain, type, protocol);
	return set_cloexec_or_close(fd);
}

int os_accept_cloexec(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;

	fd = accept(sockfd, addr, addrlen);
	
	return set_cloexec_or_close(fd);
}

static ssize_t 
recvmsg_cloexec_fallback(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t len;
	struct cmsghdr *cmsg;
	unsigned char *data;
	int *fd;
	int *end;

	len = recvmsg(sockfd, msg, flags);
	if (len == -1)
		return -1;

	if (!msg->msg_control || msg->msg_controllen == 0)
		return len;

	cmsg = CMSG_FIRSTHDR(msg);
	for (; cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET ||
			cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		data = CMSG_DATA(cmsg);
		end = (int *)(data + cmsg->cmsg_len - CMSG_LEN(0));
		for (fd = (int *)data; fd < end; ++fd)
			*fd = set_cloexec_or_close(*fd);
	}

	return len;
}

ssize_t os_recvmsg_cloexec(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t len;

	len = recvmsg(sockfd, msg, flags | MSG_CMSG_CLOEXEC);
	if (len >= 0)
		return len;
	if (errno != EINVAL)
		return -1;

	return recvmsg_cloexec_fallback(sockfd, msg, flags);
}

int get_iface_name(char *iface_name, int len)
{
	int r = -1;
	int flgs, ref, use, metric, mtu, win, ir;
	unsigned long int d, g, m;    
	char devname[20];
	FILE *fp = NULL;

	fp = fopen("/proc/net/route", "r");
	if(!fp) {
		perror("fopen error!\n");
		return -1;
	}

	if (fscanf(fp, "%*[^\n]\n") < 0) {
		fclose(fp);
		return -1;
	}

	while (1) {
		r = fscanf(fp, "%19s%lx%lx%X%d%d%d%lx%d%d%d\n",
				devname, &d, &g, &flgs, &ref, &use,
				&metric, &m, &mtu, &win, &ir);

		if (r != 11) {
			if ((r < 0) && feof(fp)) {
				break;
			}
			continue;
		}

		strncpy(iface_name, devname, len);
		fclose(fp);

		return 0;
	}

	fclose(fp);

	return -1;
}

int get_local_ip(const char *eth_inf, char *ip)
{
	struct sockaddr_in sin;
	struct ifreq ifr;
	int sd;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		printf("socket error: %s\n", strerror(errno));
		return -1;
	}

	strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	/* if error: No such device */
	if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
		printf("ioctl error: %s\n", strerror(errno));
		close(sd);

		return -1;
	}

	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	snprintf(ip, 16, "%s", inet_ntoa(sin.sin_addr));

	close(sd);

	return 0;
}

int mkdir_r(const char *path, mode_t mode)
{
	char *temp = strdup(path);
	char *pos = temp;

	if (path == NULL) {
		return -1;
	}

	/* remove prefix './' or '/' */
	if (strncmp(temp, "/", 1) == 0) {
		pos += 1;
	} else if (strncmp(temp, "./", 2) == 0) {
		pos += 2;
	}

	/* recursively create dir */
	for ( ; *pos != '\0'; ++ pos) {
		if (*pos == '/') {
			*pos = '\0';
			mkdir(temp, mode);
			*pos = '/';
		}
	}

	if (*(pos - 1) != '/')
		mkdir(temp, mode);

	free(temp);

	return 0;
}
