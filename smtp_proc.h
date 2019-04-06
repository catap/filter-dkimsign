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
#include <netinet/in.h>

#include <netinet/in.h>

struct inx_addr {
	int af;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

int smtp_register_filter_connect(void (*)(char *, int, struct timespec *,
    char *, char *, uint64_t, uint64_t, char *, struct inx_addr *));
int smtp_register_filter_data(void (*)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t));
int smtp_register_filter_dataline(void (*)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t, char *));
int smtp_register_filter_commit(void (*)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t));
int smtp_in_register_report_disconnect(void (*)(char *, int, struct timespec *,
    char *, char *, uint64_t));
void smtp_filter_proceed(uint64_t, uint64_t);
void smtp_filter_reject(uint64_t, uint64_t, int, const char *, ...)
	__attribute__((__format__ (printf, 4, 5)));
void smtp_filter_disconnect(uint64_t, uint64_t, const char *, ...)
	__attribute__((__format__ (printf, 3, 4)));
void smtp_filter_dataline(uint64_t, uint64_t, const char *, ...)
	__attribute__((__format__ (printf, 3, 4)));
void smtp_run(int);
