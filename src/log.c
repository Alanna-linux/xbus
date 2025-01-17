/**
 * log.c
 *
 * Copyright (C) 2021 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Aug 23, 2021
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <log.h>
#include <utils.h>

static FILE *logfile = NULL;

typedef void (*log_func_t)(const char *, va_list);

static log_func_t log_handler;
static int cached_tm_mday = -1;

void set_log_handler(log_func_t func)
{
	log_handler = func;
}

static int log_timestamp(void)
{
	struct timeval tv;
	struct tm *brokendown_time;
	char string[128];

	gettimeofday(&tv, NULL);

	brokendown_time = localtime(&tv.tv_sec);
	if (brokendown_time == NULL)
		return fprintf(logfile, "[(NULL)localtime] ");

	if (brokendown_time->tm_mday != cached_tm_mday) {
		strftime(string, sizeof string, "%Y-%m-%d %Z", brokendown_time);
		fprintf(logfile, "Date: %s\n", string);

		cached_tm_mday = brokendown_time->tm_mday;
	}

	strftime(string, sizeof string, "%H:%M:%S", brokendown_time);

	return fprintf(logfile, "[%s.%03li] ", string, tv.tv_usec/1000);
}

static void common_handler(const char *fmt, va_list arg)
{
	log_timestamp();
	vfprintf(logfile, fmt, arg);
}

void print(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	log_handler(fmt, argp);
	va_end(argp);
}

XBUS_EXPORT void xbus_log(const char *fmt, ...)
{
       va_list argp;

       va_start(argp, fmt);
       log_handler(fmt, argp);
       va_end(argp);
}

void print_raw(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vfprintf(logfile, fmt, argp);
	va_end(argp);
}

void log_file_open(const char *filename)
{
	char cmd[64];

	if (logfile)
		return;

	set_log_handler(common_handler);

	if (filename != NULL && strlen(filename)) {
		logfile = fopen(filename, "a");
		snprintf(cmd, sizeof(cmd), "echo > %s", filename);
		system(cmd);
	}

	if (logfile == NULL)
		logfile = stderr;
	else
		setvbuf(logfile, NULL, _IOLBF, 256);
}

void log_file_close(void)
{
	if ((logfile != stderr) && (logfile != NULL))
		fclose(logfile);
	logfile = stderr;
}
