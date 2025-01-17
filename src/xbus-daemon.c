/**
 * xbus-daemon.c
 *
 * Copyright (C) 2025 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Jan 17, 2024
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <uapi/xbus.h>

int main(int argc, char **argv)
{
	int ret;

	/* log_file_open("/var/log/xbus.log"); */
	ret = xbus_init_s();
	if (ret < 0) {
		printf("init xbus error\n");
		abort();
	}

	for (;;)
		xbus_run_s();

	return 0;
}
