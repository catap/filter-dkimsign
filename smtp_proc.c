/*
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/time.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "smtp_proc.h"

#define NITEMS(x) (sizeof(x) / sizeof(*x))

struct smtp_callback;
struct smtp_request;

extern struct event_base *current_base;

static int smtp_register(char *, char *, char *, void *);
static ssize_t smtp_getline(char ** restrict, size_t * restrict);
static void smtp_newline(int, short, void *);
static void smtp_connect(struct smtp_callback *, int, struct timespec *,
    uint64_t, uint64_t, char *);
static void smtp_data(struct smtp_callback *, int, struct timespec *,
    uint64_t, uint64_t, char *);
static void smtp_dataline(struct smtp_callback *, int, struct timespec *,
    uint64_t, uint64_t, char *);
static void smtp_in_link_disconnect(struct smtp_callback *, int, struct timespec *,
    uint64_t, char *);
static void smtp_printf(const char *, ...)
	__attribute__((__format__ (printf, 1, 2)));
static void smtp_vprintf(const char *, va_list);
static void smtp_write(int, short, void *);

struct smtp_writebuf {
	char *buf;
	size_t bufsize;
	size_t buflen;
};

struct smtp_callback {
	char *type;
	char *phase;
	char *direction;
	union {
		void (*smtp_filter)(struct smtp_callback *, int,
		    struct timespec *, uint64_t, uint64_t, char *);
		void (*smtp_report)(struct smtp_callback *, int,
		    struct timespec *, uint64_t, char *);
	};
	void *cb;
} smtp_callbacks[] = {
        {"filter", "connect", "smtp-in", .smtp_filter = smtp_connect, NULL},
        {"filter", "data", "smtp-in", .smtp_filter = smtp_data, NULL},
        {"filter", "data-line", "smtp-in", .smtp_filter = smtp_dataline, NULL},
	{"report", "link-disconnect", "smtp-in",
	    .smtp_report = smtp_in_link_disconnect, NULL}
};

static int ready = 0;

int
smtp_register_filter_connect(void (*cb)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t, char *, struct inx_addr *))
{
	return smtp_register("filter", "connect", "smtp-in", (void *)cb);
}

int
smtp_register_filter_data(void (*cb)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t))
{
	return smtp_register("filter", "data", "smtp-in", (void *)cb);
}

int
smtp_register_filter_dataline(void (*cb)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t, char *))
{
	return smtp_register("filter", "data-line", "smtp-in", (void *)cb);
}

int
smtp_in_register_report_disconnect(void (*cb)(char *, int, struct timespec *,
    char *, char *, uint64_t))
{
	return smtp_register("report", "link-disconnect", "smtp-in", (void *)cb);
}

void
smtp_run(int debug)
{
	struct event stdinev;

	smtp_printf("register|ready\n");
	ready = 1;

	log_init(debug, LOG_MAIL);
	event_set(&stdinev, STDIN_FILENO, EV_READ | EV_PERSIST, smtp_newline,
	    &stdinev);
	event_add(&stdinev, NULL);

	if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1)
		fatal("fcntl");
	event_dispatch();
}

static ssize_t
smtp_getline(char ** restrict buf, size_t * restrict size)
{
	static char *rbuf = NULL;
	static size_t rsoff = 0, reoff = 0;
	static size_t rbsize = 0;
	char *sep;
	size_t sepoff;
	ssize_t strlen, nread;

	do {
		if (rsoff != reoff) {
			if ((sep = memchr(rbuf + rsoff, '\n', reoff - rsoff))
			    != NULL) {
				sepoff = sep - rbuf;
				if (*buf == NULL)
					*size = 0;
				if (*size < (sepoff - rsoff + 1)) {
					*size = sepoff - rsoff + 1;
					*buf = realloc(*buf, sepoff - rsoff + 1);
					if (*buf == NULL)
						fatal(NULL);
				}
				sep[0] = '\0';
				strlen = strlcpy(*buf, rbuf + rsoff, *size);
				if (strlen >= *size)
					fatalx("copy buffer too small");
				rsoff = sepoff + 1;
				return strlen;
			}
		}
		/* If we can't fill at the end, move everything back. */
		if (rbsize - reoff < 1500 && rsoff != 0) {
			memmove(rbuf, rbuf + rsoff, reoff - rsoff);
			reoff -= rsoff;
			rsoff = 0;
		}
		/* If we still can't fill alloc some new memory. */
		if (rbsize - reoff < 1500) {
			if ((rbuf = realloc(rbuf, rbsize + 4096)) == NULL)
				fatal(NULL);
			rbsize += 4096;
		}
		nread = read(STDIN_FILENO, rbuf + reoff, rbsize - reoff);
		if (nread <= 0)
			return nread;
		reoff += nread;
	} while (1);
}

static void
smtp_newline(int fd, short event, void *arg)
{
	struct event *stdinev = (struct event *)arg;
	static char *line = NULL, *linedup = NULL;
	static size_t linesize = 0;
	static size_t dupsize = 0;
	ssize_t linelen;
	char *start, *end, *type, *direction, *phase, *params;
	int version;
	struct timespec tm;
	uint64_t reqid, token;
	int i;

	while ((linelen = smtp_getline(&line, &linesize)) > 0) {
		if (dupsize < linesize) {
			if ((linedup = realloc(linedup, linesize)) == NULL)
				fatal(NULL);
			dupsize = linesize;
		}
		strlcpy(linedup, line, dupsize);
		type = line;
		if ((start = strchr(type, '|')) == NULL)
			fatalx("Invalid line received: missing version: %s", linedup);
		start++[0] = '\0';
		if ((end = strchr(start, '|')) == NULL)
			fatalx("Invalid line received: missing time: %s", linedup);
		end++[0] = '\0';
		if (strcmp(start, "1") != 0)
			fatalx("Unsupported protocol received: %s: %s", start, linedup);
		version = 1;
		start = end;
		if ((direction = strchr(start, '|')) == NULL)
			fatalx("Invalid line received: missing direction: %s", linedup);
		direction++[0] = '\0';
		tm.tv_sec = (time_t) strtoull(start, &end, 10);
		tm.tv_nsec = 0;
		if (start[0] == '\0' || (end[0] != '\0' && end[0] != '.'))
			fatalx("Invalid line received: invalid timestamp: %s", linedup);
		if (end[0] == '.') {
			start = end + 1;
			tm.tv_nsec = strtol(start, &end, 10);
			if (start[0] == '\0' || end[0] != '\0')
				fatalx("Invalid line received: invalid "
				    "timestamp: %s", linedup);
			for (i = 9 - (end - start); i > 0; i--)
				tm.tv_nsec *= 10;
		}
		if ((phase = strchr(direction, '|')) == NULL)
			fatalx("Invalid line receieved: missing phase: %s", linedup);
		phase++[0] = '\0';
		if ((start = strchr(phase, '|')) == NULL)
			fatalx("Invalid line received: missing reqid: %s", linedup);
		start++[0] = '\0';
		reqid = strtoull(start, &params, 16);
		if (start[0] == '|' || (params[0] != '|' & params[0] != '\0'))
			fatalx("Invalid line received: invalid reqid: %s", linedup);
		params++;

		for (i = 0; i < NITEMS(smtp_callbacks); i++) {
			if (strcmp(type, smtp_callbacks[i].type) == 0 &&
			    strcmp(phase, smtp_callbacks[i].phase) == 0 &&
			    strcmp(direction, smtp_callbacks[i].direction) == 0)
				break;
		}
		if (i == NITEMS(smtp_callbacks)) {
			fatalx("Invalid line received: received unregistered "
			    "%s: %s: %s", type, phase, linedup);
		}
		if (strcmp(type, "filter") == 0) {
			start = params;
			token = strtoull(start, &params, 16);
			if (start[0] == '|' || params[0] != '|')
				fatalx("Invalid line received: invalid token: %s", linedup);
			params++;
			smtp_callbacks[i].smtp_filter(&(smtp_callbacks[i]),
			    version, &tm, reqid, token, params);
		} else
			smtp_callbacks[i].smtp_report(&(smtp_callbacks[i]),
			    version, &tm, reqid, params);
	}
	if (linelen == 0 || errno != EAGAIN)
		event_del(stdinev);
}

static void
smtp_connect(struct smtp_callback *cb, int version, struct timespec *tm,
    uint64_t reqid, uint64_t token, char *params)
{
	struct inx_addr addrx;
	char *hostname;
	char *address;
	int ret;
	void (*f)(char *, int, struct timespec *,char *, char *, uint64_t,
	    uint64_t, char *, struct inx_addr *);

	hostname = params;
	if ((address = strchr(params, '|')) == NULL)
		fatalx("Invalid line received: missing address: %s", params);
	address++[0] = '\0';

	addrx.af = AF_INET;
	if (strncasecmp(address, "ipv6:", 5) == 0) {
		addrx.af = AF_INET6;
		address += 5;
	}

	ret = inet_pton(addrx.af, address, addrx.af == AF_INET ?
	    (void *)&(addrx.addr) : (void *)&(addrx.addr6));
	if (ret == 0)
		fatalx("Invalid line received: Couldn't parse address: %s", params);
	if (ret == -1)
		fatal("Couldn't convert address: %s", params);

	f = cb->cb;
	f(cb->type, version, tm, cb->direction, cb->phase, reqid, token,
	    hostname, &addrx);
}

static void
smtp_data(struct smtp_callback *cb, int version, struct timespec *tm,
    uint64_t reqid, uint64_t token, char *params)
{
	void (*f)(char *, int, struct timespec *, char *, char *, uint64_t,
	    uint64_t);

	f = cb->cb;
	f(cb->type, version, tm, cb->direction, cb->phase, reqid, token);
}

static void
smtp_dataline(struct smtp_callback *cb, int version, struct timespec *tm,
    uint64_t reqid, uint64_t token, char *line)
{
	void (*f)(char *, int, struct timespec *, char *, char *, uint64_t,
	    uint64_t, char *);

	f = cb->cb;
	f(cb->type, version, tm, cb->direction, cb->phase, reqid, token,
	    line);
}

static void
smtp_in_link_disconnect(struct smtp_callback *cb, int version,
    struct timespec *tm, uint64_t reqid, char *params)
{
	void (*f)(char *, int, struct timespec *, char *, char *, uint64_t);

	f = cb->cb;
	f(cb->type, version, tm, cb->direction, cb->phase, reqid);
}

void
smtp_filter_proceed(uint64_t reqid, uint64_t token)
{
	smtp_printf("filter-result|%016"PRIx64"|%016"PRIx64"|proceed\n", token,
	    reqid);
}

static void
smtp_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	smtp_vprintf(fmt, ap);
	va_end(ap);
}

static void
smtp_vprintf(const char *fmt, va_list ap)
{
	va_list cap;
	static struct smtp_writebuf buf = {NULL, 0, 0};
	int fmtlen;

	va_copy(cap, ap);
	fmtlen = vsnprintf(buf.buf + buf.buflen, buf.bufsize - buf.buflen, fmt,
	    ap);
	if (fmtlen == -1)
		fatal("vsnprintf");
	if (fmtlen >= buf.bufsize - buf.buflen) {
		buf.bufsize = buf.buflen + fmtlen + 1;
		buf.buf = reallocarray(buf.buf, buf.bufsize,
		    sizeof(*(buf.buf)));
		if (buf.buf == NULL)
			fatalx(NULL);
		fmtlen = vsnprintf(buf.buf + buf.buflen,
		    buf.bufsize - buf.buflen, fmt, cap);
		if (fmtlen == -1)
			fatal("vsnprintf");
	}
	va_end(cap);
	buf.buflen += fmtlen;

	if (strchr(buf.buf, '\n') != NULL)
		smtp_write(STDOUT_FILENO, EV_WRITE, &buf);
}

static void
smtp_write(int fd, short event, void *arg)
{
	struct smtp_writebuf *buf = arg;
	static struct event stdoutev;
	static int evset = 0;
	ssize_t wlen;

	if (buf->buflen == 0)
		return;
	if (event_pending(&stdoutev, EV_WRITE, NULL))
		return;
	if (!evset) {
		event_set(&stdoutev, fd, EV_WRITE, smtp_write, buf);
		evset = 1;
	}
	wlen = write(fd, buf->buf, buf->buflen);
	if (wlen == -1) {
		if (errno != EAGAIN && errno != EINTR)
			fatal("Failed to write to smtpd");
		event_add(&stdoutev, NULL);
		return;
	}
	if (wlen < buf->buflen) {
		memmove(buf->buf, buf->buf + wlen, buf->buflen - wlen);
		event_add(&stdoutev, NULL);
	}
	buf->buflen -= wlen;
}

void
smtp_filter_reject(uint64_t reqid, uint64_t token, int code,
    const char *reason, ...)
{
	va_list ap;

	if (code < 200 || code > 599)
		fatalx("Invalid reject code");

	smtp_printf("filter-result|%016"PRIx64"|%016"PRIx64"|reject|%d ", token,
	    reqid, code);
	va_start(ap, reason);
	smtp_vprintf(reason, ap);
	va_end(ap);
	smtp_printf("\n");
}

void
smtp_filter_disconnect(uint64_t reqid, uint64_t token, const char *reason, ...)
{
	va_list ap;

	smtp_printf("filter-result|%016"PRIx64"|%016"PRIx64"|disconnect|421 ",
	    token, reqid);
	va_start(ap, reason);
	smtp_vprintf(reason, ap);
	va_end(ap);
	smtp_printf("\n");
}

void
smtp_filter_dataline(uint64_t reqid, uint64_t token, const char *line, ...)
{
	va_list ap;

	smtp_printf("filter-dataline|%016"PRIx64"|%016"PRIx64"|", token, reqid);
	va_start(ap, line);
	smtp_vprintf(line, ap);
	va_end(ap);
	smtp_printf("\n");
}

static int
smtp_register(char *type, char *phase, char *direction, void *cb)
{
	int i;
	static int evinit = 0;

	if (ready)
		fatalx("Can't register when proc is running");

	if (!evinit) {
		event_init();
		evinit = 1;
	}

	for (i = 0; i < NITEMS(smtp_callbacks); i++) {
		if (strcmp(type, smtp_callbacks[i].type) == 0 &&
		    strcmp(phase, smtp_callbacks[i].phase) == 0 &&
		    strcmp(direction, smtp_callbacks[i].direction) == 0) {
			if (smtp_callbacks[i].cb != NULL) {
				errno = EALREADY;
				return -1;
			}
			smtp_callbacks[i].cb = cb;
			smtp_printf("register|%s|%s|%s\n", type, direction,
			    phase);
			return 0;
		}
	}
	errno = EINVAL;
	return -1;
}
