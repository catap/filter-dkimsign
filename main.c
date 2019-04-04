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
#include <sys/tree.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "smtp_proc.h"

struct dkim_session {
	uint64_t reqid;
	uint64_t token;
	FILE *origf;
	int parsing_headers;
	char **headers;
	int lastheader;
	union {
		SHA_CTX sha1;
		SHA256_CTX sha256;
	};
	/* Use largest hash size her */
	char bbh[SHA256_DIGEST_LENGTH];
	char bh[(((SHA256_DIGEST_LENGTH + 2) / 3) * 4) + 1];
	size_t body_whitelines;
	int has_body;
	RB_ENTRY(dkim_session) entry;
};

RB_HEAD(dkim_sessions, dkim_session) dkim_sessions = RB_INITIALIZER(NULL);
RB_PROTOTYPE(dkim_sessions, dkim_session, entry, dkim_session_cmp);

static char **sign_headers = NULL;
static size_t nsign_headers = 0;

#define HASH_SHA1 0
#define HASH_SHA256 1
static int hashalg = HASH_SHA256;

#define CRYPT_RSA 0
static int cryptalg = CRYPT_RSA;

#define CANON_SIMPLE 0
#define CANON_RELAXED 1
static int canonheader = CANON_SIMPLE;
static int canonbody = CANON_SIMPLE;

static char *domain = NULL;

void usage(void);
void dkim_err(struct dkim_session *, char *);
void dkim_errx(struct dkim_session *, char *);
void dkim_headers_set(char *);
void dkim_dataline(char *, int, struct timespec *, char *, char *, uint64_t,
    uint64_t, char *);
void dkim_disconnect(char *, int, struct timespec *, char *, char *, uint64_t);
struct dkim_session *dkim_session_new(uint64_t);
void dkim_session_free(struct dkim_session *);
int dkim_session_cmp(struct dkim_session *, struct dkim_session *);
void dkim_parse_header(struct dkim_session *, char *);
void dkim_parse_body(struct dkim_session *, char *);
void dkim_built_signature(struct dkim_session *);
int dkim_hash_update(struct dkim_session *, char *, size_t);
int dkim_hash_final(struct dkim_session *, char *);

int
main(int argc, char *argv[])
{
	int ch;
	int i;
	int debug = 0;

	while ((ch = getopt(argc, argv, "a:c:Dd:h:")) != -1) {
		switch (ch) {
		case 'a':
			if (strncmp(optarg, "rsa-", 4))
				err(1, "invalid algorithm");
			if (strcmp(optarg + 4, "sha256") == 0)
				hashalg = HASH_SHA256;
			else if (strcmp(optarg + 4, "sha1") == 0)
				hashalg = HASH_SHA1;
			else
				err(1, "invalid algorithm");
			break;
		case 'c':
			if (strncmp(optarg, "simple", 6) == 0) {
				canonheader = CANON_SIMPLE;
				optarg += 6;
			} else if (strncmp(optarg, "relaxed", 7) == 0) {
				canonheader = CANON_RELAXED;
				optarg += 7;
			} else
				err(1, "Invalid canonicalization");
			if (optarg[0] == '/') {
				if (strcmp(optarg + 1, "simple") == 0)
					canonbody = CANON_SIMPLE;
				else if (strcmp(optarg + 1, "relaxed") == 0)
					canonbody = CANON_RELAXED;
				else
					err(1, "Invalid canonicalization");
			} else if (optarg[0] == '\0')
				canonbody = CANON_SIMPLE;
			else
				err(1, "Invalid canonicalization");
			break;
		case 'd':
			domain = optarg;
			if (strlen(domain) > 255)
				err(1, "Domain too long");
			break;
		case 'D':
			debug = 1;
			break;
		case 'h':
			dkim_headers_set(optarg);
			break;
		default:
			usage();
		}
	}

	log_init(debug, LOG_MAIL);
	if (pledge("tmppath stdio", NULL) == -1)
		fatal("pledge");

	if (domain == NULL)
		usage();

	smtp_register_filter_dataline(dkim_dataline);
	smtp_in_register_report_disconnect(dkim_disconnect);
	smtp_run(debug);

	return 0;
}

void
dkim_disconnect(char *type, int version, struct timespec *tm, char *direction,
    char *phase, uint64_t reqid)
{
	struct dkim_session *session, search;

	search.reqid = reqid;
	if ((session = RB_FIND(dkim_sessions, &dkim_sessions, &search)) != NULL)
		dkim_session_free(session);
}

void
dkim_dataline(char *type, int version, struct timespec *tm, char *direction,
    char *phase, uint64_t reqid, uint64_t token, char *line)
{
	struct dkim_session *session, search;
	size_t i;
	size_t linelen;

	search.reqid = reqid;
	session = RB_FIND(dkim_sessions, &dkim_sessions, &search);
	if (session == NULL) {
		session = dkim_session_new(reqid);
		session->token = token;
	} else if (session->token != token)
		fatalx("Token incorrect");

	linelen = strlen(line);
	if (fwrite(line, 1, linelen, session->origf) < linelen)
		dkim_err(session, "Couldn't write to tempfile");

	if (linelen !=  0 && session->parsing_headers) {
		dkim_parse_header(session, line);
	} else if (linelen == 0 && session->parsing_headers) {
		session->parsing_headers = 0;
	} else if (line[0] == '.' && line[1] =='\0') {
		if (canonbody == CANON_SIMPLE && !session->has_body) {
			if (dkim_hash_update(session, "\r\n", 2) == 0)
				return;
		}
		if (dkim_hash_final(session, session->bbh) == 0)
			return;
		EVP_EncodeBlock(session->bh, session->bbh,
		    hashalg == HASH_SHA1 ? SHA_DIGEST_LENGTH :
		    SHA256_DIGEST_LENGTH);
		dkim_built_signature(session);
	} else
		dkim_parse_body(session, line);
}

struct dkim_session *
dkim_session_new(uint64_t reqid)
{
	struct dkim_session *session;
	char origfile[] = "/tmp/filter-dkimXXXXXX";
	int fd;

	if ((session = calloc(1, sizeof(*session))) == NULL)
		fatal(NULL);

	session->reqid = reqid;
	if ((fd = mkstemp(origfile)) == -1) {
		dkim_err(session, "Can't open tempfile");
		return NULL;
	}
	if (unlink(origfile) == -1)
		log_warn("Failed to unlink tempfile %s", origfile);
	if ((session->origf = fdopen(fd, "r+")) == NULL) {
		dkim_err(session, "Can't open tempfile");
		return NULL;
	}
	session->parsing_headers = 1;

	if (hashalg == HASH_SHA1)
		SHA1_Init(&(session->sha1));
	else
		SHA256_Init(&(session->sha256));
	session->body_whitelines = 0;
	session->headers = calloc(1, sizeof(*(session->headers)));
	if (session->headers == NULL) {
		dkim_err(session, "Can't save headers");
		return NULL;
	}
	session->lastheader = 0;

	if (RB_INSERT(dkim_sessions, &dkim_sessions, session) != NULL)
		fatalx("session already registered");
	return session;
}

void
dkim_session_free(struct dkim_session *session)
{
	size_t i;

	RB_REMOVE(dkim_sessions, &dkim_sessions, session);
	fclose(session->origf);
	for (i = 0; session->headers[i] != NULL; i++)
		free(session->headers[i]);
	free(session->headers);
	free(session);
}

int
dkim_session_cmp(struct dkim_session *s1, struct dkim_session *s2)
{
	return (s1->reqid < s2->reqid ? -1 : s1->reqid > s2->reqid);
}

void
dkim_headers_set(char *headers)
{
	size_t i;
	int has_from = 0;

	nsign_headers = 1;

	/* We don't support FWS for the -h flag */
	for (i = 0; headers[i] != '\0'; i++) {
		/* RFC 5322 field-name */
		if (!(headers[i] >= 33 && headers[i] <= 126))
			errx(1, "-h: invalid character");
		if (headers[i] == ':') {
			/* Test for empty headers */
			if (i == 0 || headers[i - 1] == ':')
				errx(1, "-h: header can't be empty");
			nsign_headers++;
		}
		headers[i] = tolower(headers[i]);
	}
	if (headers[i - 1] == ':')
		errx(1, "-h: header can't be empty");

	sign_headers = reallocarray(NULL, nsign_headers, sizeof(*sign_headers));
	if (sign_headers == NULL)
		errx(1, NULL);

	for (i = 0; i < nsign_headers; i++) {
		sign_headers[i] = headers;
		if (i != nsign_headers - 1) {
			headers = strchr(headers, ':');
			headers++[0] = '\0';
		}
		if (strcasecmp(sign_headers[i], "from") == 0)
			has_from = 1;
	}
	if (!has_from)
		errx(1, "From header must be included");
}

void
dkim_err(struct dkim_session *session, char *msg)
{
	smtp_filter_disconnect(session->reqid, session->token,
	    "Internal server error");
	log_warn("%s", msg);
	dkim_session_free(session);
}

void
dkim_errx(struct dkim_session *session, char *msg)
{
	smtp_filter_disconnect(session->reqid, session->token,
	    "Internal server error");
	log_warnx("%s", msg);
	dkim_session_free(session);
}

void
dkim_parse_header(struct dkim_session *session, char *line)
{
	size_t i;
	size_t r, w;
	size_t linelen;
	size_t lastheader;
	int fieldname;
	char **mtmp;
	char *htmp;

	if ((line[0] == ' ' || line[0] == '\t') && !session->lastheader)
		return;
	if ((line[0] != ' ' && line[0] != '\t')) {
		for (i = 0; i < nsign_headers; i++) {
			if (strncasecmp(line, sign_headers[i],
			    strlen(sign_headers[i])) == 0) {
				break;
			}
		}
		if (i == nsign_headers) {
			session->lastheader = 0;
			return;
		}
	}

	if (canonheader == CANON_RELAXED) {
		fieldname = 1;
		for (r = w = 0; line[r] != '\0'; r++) {
			if (line[r] == ':') {
				if (line[w - 1] == ' ')
					line[w - 1] = ':';
				else
					line[w++] = ':';
				fieldname = 0;
				while (line[r + 1] == ' ' ||
				    line[r + 1] == '\t')
					r++;
				continue;
			}
			if (line[r] == ' ' || line[r] == '\t') {
				if (r != 0 && line[w - 1] == ' ')
					continue;
				else
					line[w++] = ' ';
			} else if (fieldname) {
				line[w++] = tolower(line[r]);
				continue;
			} else
				line[w++] = line[r];
		}
		linelen = line[w - 1] == ' ' ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	for (lastheader = 0; session->headers[lastheader] != NULL; lastheader++)
		continue;
	if (!session->lastheader) {
		mtmp = reallocarray(session->headers, lastheader + 1,
		    sizeof(*mtmp));
		if (mtmp == NULL) {
			dkim_err(session, "Can't store header");
			return;
		}
		session->headers = mtmp;
		
		session->headers[lastheader] = strdup(line);
		session->headers[lastheader + 1 ] = NULL;
		session->lastheader = 1;
	} else {
		lastheader--;
		linelen += strlen(session->headers[lastheader]);
		if (canonheader == CANON_SIMPLE)
			linelen += 2;
		linelen++;
		htmp = reallocarray(session->headers[lastheader], linelen,
		    sizeof(*htmp));
		if (htmp == NULL) {
			dkim_err(session, "Can't store header");
			return;
		}
		session->headers[lastheader] = htmp;
		if (canonheader == CANON_SIMPLE) {
			if (strlcat(htmp, "\r\n", linelen) >= linelen)
				fatalx("Missized header");
		}
		if (strlcat(htmp, line, linelen) >= linelen)
			fatalx("Missized header");
	}
}

void
dkim_parse_body(struct dkim_session *session, char *line)
{
	size_t r, w;
	size_t linelen;
	if (line[0] == '\0') {
		session->body_whitelines++;
		return;
	}

	while (session->body_whitelines--) {
		if (dkim_hash_update(session, "\r\n", 2) == 0)
			return;
	}
	session->body_whitelines = 0;

	session->has_body = 1;
	if (canonbody == CANON_RELAXED) {
		for (r = w = 0; line[r] != '\0'; r++) {
			if (line[r] == ' ' || line[r] == '\t') {
				if (r != 0 && line[w - 1] == ' ')
					continue;
				else
					line[w++] = ' ';
			} else
				line[w++] = line[r];
		}
		linelen = line[w - 1] == ' ' ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	if (dkim_hash_update(session, line, linelen) == 0)
		return;
	if (dkim_hash_update(session, "\r\n", 2) == 0)
		return;
}

void
dkim_built_signature(struct dkim_session *session)
{
	char *signature;
	size_t signaturesize = 1024;
	size_t signaturelen = 0;
	size_t linelen = 0;
	size_t ncopied;

	if ((signature = malloc(signaturesize)) == NULL) {
		dkim_err(session, "Can't create signature");
		return;
	}

	do {
		ncopied = strlcpy(signature, "DKIM-Signature: v=1; a=",
		    signaturesize);
	if (ncopied >= signaturesize)
	if (cryptalg == CRYPT_RSA)
		(void) strlcat(signature, "rsa", signaturesize);
	if (hashalg == HASH_SHA1)
		(void) strlcat(signature, "-sha1; ", signaturesize);
	else
		(void) strlcat(signature, "-sha256; ", signaturesize);
	if (canonheader != CANON_SIMPLE || canonbody != CANON_SIMPLE) {
		if (canonheader == CANON_SIMPLE)
			(void) strlcat(signature, "c=simple", signaturesize);
		else
			(void) strlcat(signature, "c=relaxed", signaturesize);
	}
	if (canonbody != CANON_SIMPLE)
		(void) strlcat(signature, "/relaxed", signaturesize);

	(void) strlcat(signature, "d=", signaturesize);
	(void) strlcat(signature, domain, signaturesize);
	(void) strlcat(signature, "; ", signaturesize);
	printf("%s\n", signature);
}

int
dkim_hash_update(struct dkim_session *session, char *buf, size_t len)
{
	if (hashalg == HASH_SHA1) {
		if (SHA1_Update(&(session->sha1), buf, len) == 0) {
			dkim_errx(session, "Unable to update hash");
			return 0;
		}
	} else {
		if (SHA256_Update(&(session->sha256), buf, len) == 0) {
			dkim_errx(session, "Unable to update hash");
			return 0;
		}
	}
	return 1;
}

int
dkim_hash_final(struct dkim_session *session, char *dest)
{
	if (hashalg == HASH_SHA1) {
		if (SHA1_Final(dest, &(session->sha1)) == 0) {
			dkim_errx(session, "Unable to finalize hash");
			return 0;
		}
	} else {
		if (SHA256_Final(dest, &(session->sha256)) == 0) {
			dkim_errx(session, "Unable to finalize hash");
			return 0;
		}
	}
	return 1;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-a signalg] [-c canonicalization] -d domain -h headerfields\n", getprogname());
	exit(1);
}

RB_GENERATE(dkim_sessions, dkim_session, entry, dkim_session_cmp);
