/*
 * Copyright (c) 2020 Martijn van Duren <martijn@openbsd.org>
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

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "mheader.h"

char *
osmtpd_mheader_skip_sp(char *ptr, int optional)
{
	if (ptr[0] == 0x20)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_htab(char *ptr, int optional)
{
	if (ptr[0] == 0x9)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_wsp(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_sp(start, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_htab(start, 0)) != NULL)
		return ptr;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_crlf(char *ptr, int optional)
{
	if (ptr[0] == 13 && ptr[1] == 10)
		return ptr + 2;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_vchar(char *ptr, int optional)
{
	if (ptr[0] >= 0x21 && ptr[0] <= 0x7e)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_lf(char *ptr, int optional)
{
	if (ptr[0] == 0xa)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_cr(char *ptr, int optional)
{
	if (ptr[0] == 0xd)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_alpha(char *ptr, int optional)
{
	if ((ptr[0] >= 0x41 && ptr[0] <= 0x5a) ||
	    (ptr[0] >= 0x61 && ptr[0] <= 0x7a))
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_digit(char *ptr, int optional)
{
	if (ptr[0] >= 0x30 && ptr[0] <= 0x39)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_dquote(char *ptr, int optional)
{
	if (ptr[0] == 0x22)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_obs_fws(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;

	ptr = prev;
	while (1) {
		if ((ptr = osmtpd_mheader_skip_crlf(ptr, 0)) == NULL)
			return prev;
		if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
		while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
			prev = ptr;
		ptr = prev;
	}
}

char *
osmtpd_mheader_skip_fws(char *ptr, int optional)
{
	char *start = ptr, *prev = ptr;

	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	if ((ptr = osmtpd_mheader_skip_crlf(prev, 1)) == prev)
		ptr = start;
	if ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) == NULL)
		return osmtpd_mheader_skip_obs_fws(start, optional);
	prev = ptr;
	while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL)
		prev = ptr;
	return prev;
}

char *
osmtpd_mheader_skip_obs_no_ws_ctl(char *ptr, int optional)
{
	if ((ptr[0] >= 1 && ptr[0] <= 8) || ptr[0] == 11 || ptr[0] == 12 ||
	    (ptr[0] >= 14 && ptr[0] <= 31) || ptr[0] == 127)
		return ptr + 1;
	return optional ? ptr : NULL;
}

char *
osmtpd_mheader_skip_obs_ctext(char *ptr, int optional)
{
	return osmtpd_mheader_skip_obs_no_ws_ctl(ptr, optional);
}

char *
osmtpd_mheader_skip_ctext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr[0] >= 33 && ptr[0] <= 39) || (ptr[0] >= 42 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_mheader_skip_obs_ctext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_obs_qp(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_mheader_skip_obs_no_ws_ctl(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_lf(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_cr(start + 1, 0)) != NULL))
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_quoted_pair(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == '\\' && (
	    (ptr = osmtpd_mheader_skip_vchar(start + 1, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_wsp(start + 1, 0)) != NULL))
		return ptr;
	return osmtpd_mheader_skip_obs_qp(start, optional);
}

char *
osmtpd_mheader_skip_ccontent(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_ctext(ptr, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_quoted_pair(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_comment(start, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_comment(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr++[0] != '(')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if (ptr[0] == ')')
			return ptr + 1;
		if ((ptr = osmtpd_mheader_skip_ccontent(ptr, 0)) == NULL)
			return optional ? start : NULL;
	}
}

char *
osmtpd_mheader_skip_cfws(char *ptr, int optional)
{
	char *start = ptr, *prev;

	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_comment(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr == start && !optional ? NULL : ptr;
}

char *
osmtpd_mheader_skip_atext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_alpha(start, 0)) != NULL ||
	    (ptr = osmtpd_mheader_skip_digit(start, 0)) != NULL)
		return ptr;
	ptr = start;
	if (ptr[0] == '!' || ptr[0] == '#' || ptr[0] == '$' || ptr[0] == '%' ||
	    ptr[0] == '&' || ptr[0] == '\'' || ptr[0] == '*' || ptr[0] == '+' ||
	    ptr[0] == '-' || ptr[0] == '/' || ptr[0] == '=' || ptr[0] == '?' ||
	    ptr[0] == '^' || ptr[0] == '_' || ptr[0] == '`' || ptr[0] == '{' ||
	    ptr[0] == '|' || ptr[0] == '}' || ptr[0] == '~')
		return ptr + 1;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_atom(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_mheader_skip_atext(ptr, 1);
	} while (prev != ptr);
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_dot_atom_text(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
		return optional ? start : NULL;
	do {
		prev = ptr;
		ptr = osmtpd_mheader_skip_atext(ptr, 1);
	} while (ptr != prev);

	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_mheader_skip_atext(ptr, 0)) == NULL)
			return prev;
		do {
			prev = ptr;
			ptr = osmtpd_mheader_skip_atext(ptr, 1);
		} while (ptr != prev);
	}
	return ptr;
}

char *
osmtpd_mheader_skip_dot_atom(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dot_atom_text(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}


char *
osmtpd_mheader_skip_obs_qtext(char *ptr, int optional)
{
	return osmtpd_mheader_skip_obs_no_ws_ctl(ptr, optional);
}

char *
osmtpd_mheader_skip_qtext(char *ptr, int optional)
{
	char *start = ptr;

	if (ptr[0] == 33 || (ptr[0] >= 35 && ptr[0] <= 91) ||
	    (ptr[0] >= 93 && ptr[0] <= 126))
		return ptr + 1;
	if ((ptr = osmtpd_mheader_skip_obs_qtext(ptr, 0)) != NULL)
		return ptr;
	return optional ? start : NULL;
}

char *
osmtpd_mheader_skip_qcontent(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_qtext(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_pair(start, optional);
}

char *
osmtpd_mheader_skip_quoted_string(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_dquote(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		if ((ptr = osmtpd_mheader_skip_qcontent(ptr, 0)) == NULL)
			break;
		prev = ptr;
	}
	if ((ptr = osmtpd_mheader_skip_dquote(prev, 0)) == NULL)
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_word(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_string(start, optional);
}

char *
osmtpd_mheader_skip_obs_phrase(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) != NULL)
			continue;
		ptr = prev;
		if (ptr[0] == '.')
			continue;
		if ((ptr = osmtpd_mheader_skip_cfws(ptr, 0)) != NULL)
			continue;
		return prev;
	}
}

char *
osmtpd_mheader_skip_phrase(char *ptr, int optional)
{
	/* obs-phrase is a superset of phrae */
	return osmtpd_mheader_skip_obs_phrase(ptr, optional);
#if 0
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
			return prev;
	}
#endif
}

char *
osmtpd_mheader_skip_obs_local_part(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (ptr[0] == '.') {
		ptr++;
		if ((ptr = osmtpd_mheader_skip_word(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
	return ptr;
}

char *
osmtpd_mheader_skip_local_part(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dot_atom(ptr, 0)) != NULL)
		return ptr;
	ptr = start;
	if ((ptr = osmtpd_mheader_skip_quoted_string(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_obs_local_part(start, optional);
}

char *
osmtpd_mheader_skip_obs_dtext(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_obs_no_ws_ctl(ptr, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_quoted_pair(start, optional);
}

char *
osmtpd_mheader_skip_dtext(char *ptr, int optional)
{
	if ((ptr[0] >= 33 && ptr[0] <= 90) || (ptr[0] >= 94 && ptr[0] <= 126))
		return ptr + 1;
	return osmtpd_mheader_skip_obs_dtext(ptr, optional);

}

char *
osmtpd_mheader_skip_domain_literal(char *ptr, int optional)
{
	char *start = ptr, *prev;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '[')
		return optional ? start : NULL;
	while (1) {
		ptr = osmtpd_mheader_skip_fws(ptr, 1);
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_dtext(ptr, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	if (ptr[0] != ']')
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_obs_domain(char *ptr, int optional)
{
	char *start = ptr, *prev;

	if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) == NULL)
		return optional ? start : NULL;
	prev = ptr;
	while (1) {
		if (ptr++[0] != '.')
			return prev;
		if ((ptr = osmtpd_mheader_skip_atom(ptr, 0)) == NULL)
			return prev;
		prev = ptr;
	}
}

char *
osmtpd_mheader_skip_domain(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_dot_atom(start, 0)) != NULL)
		return ptr;
	if ((ptr = osmtpd_mheader_skip_domain_literal(start, 0)) != NULL)
		return ptr;
	return osmtpd_mheader_skip_obs_domain(start, optional);
}

char *
osmtpd_mheader_skip_display_name(char *ptr, int optional)
{
	return osmtpd_mheader_skip_phrase(ptr, optional);
}

char *
osmtpd_mheader_skip_obs_domain_list(char *ptr, int optional)
{
	char *start = ptr, *prev;

	while (1) {
		if (ptr[0] == ',') {
			ptr++;
			prev = ptr;
			continue;
		} else if ((ptr = osmtpd_mheader_skip_cfws(ptr, 0)) != NULL) {
			prev = ptr;
			continue;
		}
		break;
	}
	ptr = prev;

	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	while (1) {
		if (ptr[0] != ',')
			break;
		ptr++;
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		if (ptr[0] != '@')
			continue;
		prev = ptr;
		if ((ptr = osmtpd_mheader_skip_domain(ptr + 1, 0)) == NULL) {
			ptr = prev;
			break;
		}
	}
	return ptr;
}

char *
osmtpd_mheader_skip_obs_route(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_obs_domain_list(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != ':')
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_addr_spec(char *ptr, int optional)
{
	char *start = ptr;

	if ((ptr = osmtpd_mheader_skip_local_part(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '@')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_domain(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

char *
osmtpd_mheader_skip_obs_angle_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_obs_route(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if ((ptr = osmtpd_mheader_skip_addr_spec(ptr, 0)) == NULL)
		return optional ? start : NULL;
	if (ptr++[0] != '>')
		return optional ? start : NULL;
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_angle_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_cfws(ptr, 1);
	if (ptr++[0] != '<')
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	if ((ptr = osmtpd_mheader_skip_addr_spec(ptr, 0)) == NULL)
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	if (ptr++[0] != '>')
		return osmtpd_mheader_skip_obs_angle_addr(start, optional);
	return osmtpd_mheader_skip_cfws(ptr, 1);
}

char *
osmtpd_mheader_skip_name_addr(char *ptr, int optional)
{
	char *start = ptr;

	ptr = osmtpd_mheader_skip_display_name(ptr, 1);
	if ((ptr = osmtpd_mheader_skip_angle_addr(ptr, 0)) == NULL)
		return optional ? start : NULL;
	return ptr;
}

/* Return the domain component of the first mailbox */
char *
osmtpd_mheader_from_domain(char *ptr)
{
	char *tmp;

	/* from */
	if (strncasecmp(ptr, "from:", 5) == 0) {
		ptr += 5;
	/* obs-from */
	} else if (strncasecmp(ptr, "from", 4) == 0) {
		ptr += 4;
		do {
			tmp = ptr;
		} while ((ptr = osmtpd_mheader_skip_wsp(ptr, 0)) != NULL);
		ptr = tmp;
		if (ptr++[0] != ':')
			return NULL;
	} else {
		errno = EINVAL;
		return NULL;
	}

	/* Both from and obs-from use Mailbox-list CRLF */
	/* obs-mbox-list has just a prefix compared to mailbox-list */
	while (1) {
		tmp = ptr;
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		if (ptr++[0] != ',') {
			ptr = tmp;
			break;
		}
	}
	/* We're only interested in the first mailbox */
	if (osmtpd_mheader_skip_name_addr(ptr, 0) != NULL) {
		ptr = osmtpd_mheader_skip_display_name(ptr, 1);
		ptr = osmtpd_mheader_skip_cfws(ptr, 1);
		/* < */
		ptr++;
		/* addr-spec */
		ptr = osmtpd_mheader_skip_local_part(ptr, 0);
		/* @ */
		ptr++;
		tmp = osmtpd_mheader_skip_domain(ptr, 0);
		return strndup(ptr, tmp - ptr);
	}
	if (osmtpd_mheader_skip_addr_spec(ptr, 0) != NULL) {
		ptr = osmtpd_mheader_skip_local_part(ptr, 0);
		/* @ */
		ptr++;
		tmp = osmtpd_mheader_skip_domain(ptr, 0);
		return strndup(ptr, tmp - ptr);
	}
	errno = EINVAL;
	return NULL;
}
