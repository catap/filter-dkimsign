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

char *osmtpd_mheader_skip_sp(char *, int);
char *osmtpd_mheader_skip_htab(char *, int);
char *osmtpd_mheader_skip_wsp(char *, int);
char *osmtpd_mheader_skip_crlf(char *, int);
char *osmtpd_mheader_skip_vchar(char *, int);
char *osmtpd_mheader_skip_lf(char *, int);
char *osmtpd_mheader_skip_cr(char *, int);
char *osmtpd_mheader_skip_alpha(char *, int);
char *osmtpd_mheader_skip_digit(char *, int);
char *osmtpd_mheader_skip_dquote(char *, int);
char *osmtpd_mheader_skip_obs_fws(char *, int);
char *osmtpd_mheader_skip_fws(char *, int);
char *osmtpd_mheader_skip_obs_no_ws_ctl(char *, int);
char *osmtpd_mheader_skip_obs_ctext(char *, int);
char *osmtpd_mheader_skip_obs_qp(char *, int);
char *osmtpd_mheader_skip_quoted_pair(char *, int);
char *osmtpd_mheader_skip_ctext(char *, int);
char *osmtpd_mheader_skip_ccontent(char *, int);
char *osmtpd_mheader_skip_comment(char *, int);
char *osmtpd_mheader_skip_cfws(char *, int);
char *osmtpd_mheader_skip_atext(char *, int);
char *osmtpd_mheader_skip_atom(char *, int);
char *osmtpd_mheader_skip_dot_atom_text(char *, int);
char *osmtpd_mheader_skip_dot_atom(char *, int);
char *osmtpd_mheader_skip_obs_qtext(char *, int);
char *osmtpd_mheader_skip_qtext(char *, int);
char *osmtpd_mheader_skip_qcontent(char *, int);
char *osmtpd_mheader_skip_quoted_string(char *, int);
char *osmtpd_mheader_skip_word(char *, int);
char *osmtpd_mheader_skip_obs_phrase(char *, int);
char *osmtpd_mheader_skip_phrase(char *, int);
char *osmtpd_mheader_skip_obs_local_part(char *, int);
char *osmtpd_mheader_skip_local_part(char *, int);
char *osmtpd_mheader_skip_obs_dtext(char *, int);
char *osmtpd_mheader_skip_dtext(char *, int);
char *osmtpd_mheader_skip_domain_literal(char *, int);
char *osmtpd_mheader_skip_obs_domain(char *, int);
char *osmtpd_mheader_skip_domain(char *, int);
char *osmtpd_mheader_skip_display_name(char *, int);
char *osmtpd_mheader_skip_obs_domain_list(char *, int);
char *osmtpd_mheader_skip_obs_route(char *, int);
char *osmtpd_mheader_skip_addr_spec(char *, int);
char *osmtpd_mheader_skip_obs_angle_addr(char *, int);
char *osmtpd_mheader_skip_angle_addr(char *, int);
char *osmtpd_mheader_skip_name_addr(char *, int);

char *osmtpd_mheader_from_domain(char *);
