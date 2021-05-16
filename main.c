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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "openbsd-compat.h"
#include "opensmtpd.h"
#include "mheader.h"

struct dkim_signature {
	char *signature;
	size_t size;
	size_t len;
};

struct dkim_message {
	FILE *origf;
	int parsing_headers;
	char **headers;
	int lastheader;
	size_t body_whitelines;
	int has_body;
	struct dkim_signature signature;
	int err;
	EVP_MD_CTX *dctx;
};

/* RFC 6376 section 5.4.1 */
static char *dsign_headers[] = {
	"from",
	"reply-to",
	"subject",
	"date",
	"to",
	"cc",
	"resent-date",
	"resent-from",
	"resent-to",
	"resent-cc",
	"in-reply-to",
	"references",
	"list-id",
	"list-help",
	"list-unsubscribe",
	"list-subscribe",
	"list-post",
	"list-owner",
	"list-archive"
};
static char **sign_headers = dsign_headers;
static size_t nsign_headers = sizeof(dsign_headers) / sizeof(*dsign_headers);

static char *hashalg = "sha256";
static char *cryptalg = "rsa";

#define CANON_SIMPLE 0
#define CANON_RELAXED 1
static int canonheader = CANON_SIMPLE;
static int canonbody = CANON_SIMPLE;

static int addtime = 0;
static long long addexpire = 0;
static int addheaders = 0;

static char **domain = NULL;
static size_t ndomains = 0;
static char *selector = NULL;

static EVP_PKEY *pkey;
static const EVP_MD *hash_md;
static int keyid = EVP_PKEY_RSA;
static int sephash = 0;

#define DKIM_SIGNATURE_LINELEN 78

void usage(void);
void dkim_err(struct dkim_message *, char *);
void dkim_errx(struct dkim_message *, char *);
void dkim_headers_set(char *);
void dkim_dataline(struct osmtpd_ctx *, const char *);
void dkim_commit(struct osmtpd_ctx *);
void *dkim_message_new(struct osmtpd_ctx *);
void dkim_message_free(struct osmtpd_ctx *, void *);
void dkim_parse_header(struct dkim_message *, char *, int);
void dkim_parse_body(struct dkim_message *, char *);
void dkim_sign(struct osmtpd_ctx *);
int dkim_signature_printheader(struct dkim_message *, const char *);
int dkim_signature_printf(struct dkim_message *, char *, ...)
	__attribute__((__format__ (printf, 2, 3)));
int dkim_signature_normalize(struct dkim_message *);
const char *dkim_domain_select(struct dkim_message *, char *);
int dkim_signature_need(struct dkim_message *, size_t);
int dkim_sign_init(struct dkim_message *);

int
main(int argc, char *argv[])
{
	int ch;
	FILE *keyfile;
	const char *errstr;

	while ((ch = getopt(argc, argv, "a:c:d:h:k:s:tx:z")) != -1) {
		switch (ch) {
		case 'a':
			if (strncmp(optarg, "rsa-", 4) == 0) {
				cryptalg = "rsa";
				hashalg = optarg + 4;
				keyid = EVP_PKEY_RSA;
				sephash = 0;
#ifdef HAVE_ED25519
			} else if (strncmp(optarg, "ed25519-", 8) == 0) {
				hashalg = optarg + 8;
				cryptalg = "ed25519";
				keyid = EVP_PKEY_ED25519;
				sephash = 1;
#endif
			} else
				osmtpd_errx(1, "invalid algorithm");
			break;
		case 'c':
			if (strncmp(optarg, "simple", 6) == 0) {
				canonheader = CANON_SIMPLE;
				optarg += 6;
			} else if (strncmp(optarg, "relaxed", 7) == 0) {
				canonheader = CANON_RELAXED;
				optarg += 7;
			} else
				osmtpd_err(1, "Invalid canonicalization");
			if (optarg[0] == '/') {
				if (strcmp(optarg + 1, "simple") == 0)
					canonbody = CANON_SIMPLE;
				else if (strcmp(optarg + 1, "relaxed") == 0)
					canonbody = CANON_RELAXED;
				else
					osmtpd_err(1,
					    "Invalid canonicalization");
			} else if (optarg[0] == '\0')
				canonbody = CANON_SIMPLE;
			else
				osmtpd_err(1, "Invalid canonicalization");
			break;
		case 'd':
			if ((domain = reallocarray(domain, ndomains + 1,
			    sizeof(*domain))) == NULL)
				osmtpd_err(1, "malloc");
			domain[ndomains++] = optarg;
			break;
		case 'h':
			dkim_headers_set(optarg);
			break;
		case 'k':
			if ((keyfile = fopen(optarg, "r")) == NULL)
				osmtpd_err(1, "Can't open key file (%s)",
				    optarg);
			pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
			if (pkey == NULL)
				osmtpd_errx(1, "Can't read key file");
			fclose(keyfile);
			break;
		case 's':
			selector = optarg;
			break;
		case 't':
			addtime = 1;
			break;
		case 'x':
			addexpire = strtonum(optarg, 1, INT64_MAX, &errstr);
			if (addexpire == 0)
				osmtpd_errx(1, "Expire offset is %s", errstr);
			break;
		case 'z':
			addheaders++;
			break;
		default:
			usage();
		}
	}

	OpenSSL_add_all_digests();

	if (pledge("tmppath stdio", NULL) == -1)
		osmtpd_err(1, "pledge");

	if ((hash_md = EVP_get_digestbyname(hashalg)) == NULL)
		osmtpd_errx(1, "Can't find hash: %s", hashalg);

	if (domain == NULL || selector == NULL || pkey == NULL)
		usage();

	if (EVP_PKEY_id(pkey) != keyid)
		osmtpd_errx(1, "Key is not of type %s", cryptalg);

	osmtpd_register_filter_dataline(dkim_dataline);
	osmtpd_register_filter_commit(dkim_commit);
	osmtpd_local_message(dkim_message_new, dkim_message_free);
	osmtpd_run();

	return 0;
}

void
dkim_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct dkim_message *message = ctx->local_message;
	char *linedup;
	size_t linelen;

	if (message->err) {
		if (line[0] == '.' && line[1] =='\0')
			osmtpd_filter_dataline(ctx, ".");
		return;
	}

	linelen = strlen(line);
	if (fprintf(message->origf, "%s\n", line) < (int) linelen)
		dkim_errx(message, "Couldn't write to tempfile");

	if (line[0] == '.' && line[1] =='\0') {
		dkim_sign(ctx);
	} else if (linelen !=  0 && message->parsing_headers) {
		if (line[0] == '.')
			line++;
		if ((linedup = strdup(line)) == NULL)
			osmtpd_err(1, "strdup");
		dkim_parse_header(message, linedup, 0);
		free(linedup);
	} else if (linelen == 0 && message->parsing_headers) {
		if (addheaders > 0 && !dkim_signature_printf(message, "; "))
			return;
		message->parsing_headers = 0;
	} else {
		if (line[0] == '.')
			line++;
		if ((linedup = strdup(line)) == NULL)
			osmtpd_err(1, "strdup");
		dkim_parse_body(message, linedup);
		free(linedup);
	}
}

void
dkim_commit(struct osmtpd_ctx *ctx)
{
	struct dkim_message *message = ctx->local_message;

	if (message->err)
		osmtpd_filter_disconnect(ctx, "Internal server error");
	else
		osmtpd_filter_proceed(ctx);
}

void *
dkim_message_new(struct osmtpd_ctx *ctx)
{
	struct dkim_message *message;

	if ((message = calloc(1, sizeof(*message))) == NULL) {
		dkim_err(message, "Failed to create message context");
		return NULL;
	}

	if ((message->origf = tmpfile()) == NULL) {
		dkim_err(message, "Failed to open tempfile");
		goto fail;
	}
	message->parsing_headers = 1;

	message->body_whitelines = 0;
	message->headers = calloc(1, sizeof(*(message->headers)));
	if (message->headers == NULL) {
		dkim_err(message, "Can't save headers");
		goto fail;
	}
	message->lastheader = 0;
	message->signature.signature = NULL;
	message->signature.size = 0;
	message->signature.len = 0;
	message->err = 0;

	if (!dkim_signature_printf(message,
	    "DKIM-Signature: v=%s; a=%s-%s; c=%s/%s; s=%s; ", "1",
	    cryptalg, hashalg,
	    canonheader == CANON_SIMPLE ? "simple" : "relaxed",
	    canonbody == CANON_SIMPLE ? "simple" : "relaxed", selector))
		goto fail;
	if (addheaders > 0 && !dkim_signature_printf(message, "z="))
		goto fail;

	if ((message->dctx = EVP_MD_CTX_new()) == NULL) {
		dkim_errx(message, "Failed to create hash context");
		goto fail;
	}
	if (EVP_DigestInit_ex(message->dctx, hash_md, NULL) <= 0) {
		dkim_errx(message, "Failed to initialize hash context");
		goto fail;
	}
	return message;
fail:
	free(message->headers);
	EVP_MD_CTX_free(message->dctx);
	free(message);
	return NULL;
}

void
dkim_message_free(struct osmtpd_ctx *ctx, void *data)
{
	struct dkim_message *message = data;
	size_t i;

	fclose(message->origf);
	EVP_MD_CTX_free(message->dctx);
	free(message->signature.signature);
	for (i = 0; message->headers[i] != NULL; i++)
		free(message->headers[i]);
	free(message->headers);
	free(message);
}

void
dkim_headers_set(char *headers)
{
	size_t i;
	int has_from = 0;

	nsign_headers = 1;

	for (i = 0; headers[i] != '\0'; i++) {
		/* RFC 5322 field-name */
		if (!(headers[i] >= 33 && headers[i] <= 126))
			osmtpd_errx(1, "-h: invalid character");
		if (headers[i] == ':') {
			/* Test for empty headers */
			if (i == 0 || headers[i - 1] == ':')
				osmtpd_errx(1, "-h: header can't be empty");
			nsign_headers++;
		}
		headers[i] = tolower(headers[i]);
	}
	if (headers[i - 1] == ':')
		osmtpd_errx(1, "-h: header can't be empty");

	if ((sign_headers = reallocarray(NULL, nsign_headers + 1,
	    sizeof(*sign_headers))) == NULL)
		osmtpd_errx(1, NULL);

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
		osmtpd_errx(1, "From header must be included");
}

void
dkim_err(struct dkim_message *message, char *msg)
{
	message->err = 1;
	fprintf(stderr, "%s: %s\n", msg, strerror(errno));
}

void
dkim_errx(struct dkim_message *message, char *msg)
{
	message->err = 1;
	fprintf(stderr, "%s\n", msg);
}

void
dkim_parse_header(struct dkim_message *message, char *line, int force)
{
	size_t i;
	size_t r, w;
	size_t linelen;
	size_t lastheader;
	size_t hlen;
	int fieldname = 0;
	char **mtmp;
	char *htmp;
	char *tmp;

	if (addheaders == 2 && !force &&
	    !dkim_signature_printheader(message, line))
		return;

	if ((line[0] == ' ' || line[0] == '\t') && !message->lastheader)
		return;
	if ((line[0] != ' ' && line[0] != '\t')) {
		message->lastheader = 0;
		for (i = 0; i < nsign_headers; i++) {
			hlen = strlen(sign_headers[i]);
			if  (strncasecmp(line, sign_headers[i], hlen) == 0) {
				while (line[hlen] == ' ' || line[hlen] == '\t')
					hlen++;
				if (line[hlen] != ':')
					continue;
				break;
			}
		}
		if (i == nsign_headers && !force)
			return;
	}

	if (addheaders == 1 && !force &&
	    !dkim_signature_printheader(message, line))
		return;

	if (canonheader == CANON_RELAXED) {
		if (!message->lastheader)
			fieldname = 1;
		for (r = w = 0; line[r] != '\0'; r++) {
			if (line[r] == ':' && fieldname) {
				if (w > 0 && line[w - 1] == ' ')
					line[w - 1] = ':';
				else
					line[w++] = ':';
				fieldname = 0;
				while (line[r + 1] == ' ' ||
				    line[r + 1] == '\t')
					r++;
				continue;
			}
			if (line[r] == ' ' || line[r] == '\t' ||
			    line[r] == '\r' || line[r] == '\n') {
				if (r != 0 && w != 0 && line[w - 1] == ' ')
					continue;
				else
					line[w++] = ' ';
			} else if (fieldname) {
				line[w++] = tolower(line[r]);
				continue;
			} else
				line[w++] = line[r];
		}
		linelen = (w != 0 && line[w - 1] == ' ') ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	for (lastheader = 0; message->headers[lastheader] != NULL; lastheader++)
		continue;
	if (!message->lastheader) {
		mtmp = recallocarray(message->headers, lastheader + 1,
		    lastheader + 2, sizeof(*mtmp));
		if (mtmp == NULL) {
			dkim_err(message, "Can't store header");
			return;
		}
		message->headers = mtmp;

		message->headers[lastheader] = strdup(line);
		message->headers[lastheader + 1 ] = NULL;
		message->lastheader = 1;
	} else {
		lastheader--;
		linelen += strlen(message->headers[lastheader]);
		if (canonheader == CANON_SIMPLE)
			linelen += 2;
		linelen++;
		htmp = reallocarray(message->headers[lastheader], linelen,
		    sizeof(*htmp));
		if (htmp == NULL) {
			dkim_err(message, "Can't store header");
			return;
		}
		message->headers[lastheader] = htmp;
		if (canonheader == CANON_SIMPLE) {
			if (strlcat(htmp, "\r\n", linelen) >= linelen)
				osmtpd_errx(1, "Missized header");
		} else if (canonheader == CANON_RELAXED &&
		    (tmp = strchr(message->headers[lastheader], ':')) != NULL &&
		    tmp[1] == '\0')
			line++;

		if (strlcat(htmp, line, linelen) >= linelen)
			osmtpd_errx(1, "Missized header");
	}
}

void
dkim_parse_body(struct dkim_message *message, char *line)
{
	size_t r, w;
	size_t linelen;

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
		linelen = (w != 0 && line[w - 1] == ' ') ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	if (line[0] == '\0') {
		message->body_whitelines++;
		return;
	}

	while (message->body_whitelines--) {
		if (EVP_DigestUpdate(message->dctx, "\r\n", 2) == 0) {
			dkim_errx(message, "Can't update hash context");
			return;
		}
	}
	message->body_whitelines = 0;
	message->has_body = 1;

	if (EVP_DigestUpdate(message->dctx, line, linelen) == 0 ||
	    EVP_DigestUpdate(message->dctx, "\r\n", 2) == 0) {
		dkim_errx(message, "Can't update hash context");
		return;
	}
}

void
dkim_sign(struct osmtpd_ctx *ctx)
{
	struct dkim_message *message = ctx->local_message;
	/* Use largest hash size here */
	char bdigest[EVP_MAX_MD_SIZE];
	char digest[(((sizeof(bdigest) + 2) / 3) * 4) + 1];
	char *b;
	const char *sdomain = domain[0], *tsdomain;
	time_t now;
	ssize_t i;
	size_t linelen = 0;
	char *tmp, *tmp2;
	int digestsz;

	if (addtime || addexpire)
		now = time(NULL);
	if (addtime && !dkim_signature_printf(message, "t=%lld; ",
	    (long long)now))
		return;
	if (addexpire != 0 && !dkim_signature_printf(message, "x=%lld; ",
	    now + addexpire < now ? INT64_MAX : now + addexpire))
		return;

	if (canonbody == CANON_SIMPLE && !message->has_body) {
		if (EVP_DigestUpdate(message->dctx, "\r\n", 2) <= 0) {
			dkim_errx(message, "Can't update hash context");
			return;
		}
	}
	if (EVP_DigestFinal_ex(message->dctx, bdigest, &digestsz) == 0) {
		dkim_errx(message, "Can't finalize hash context");
		return;
	}
	EVP_EncodeBlock(digest, bdigest, digestsz);
	if (!dkim_signature_printf(message, "bh=%s; h=", digest))
		return;
	/* Reverse order for ease of use of RFC6367 section 5.4.2 */
	for (i = 0; message->headers[i] != NULL; i++)
		continue;
	EVP_MD_CTX_reset(message->dctx);
	if (!sephash) {
		if (EVP_DigestSignInit(message->dctx, NULL, hash_md, NULL,
		    pkey) != 1) {
			dkim_errx(message, "Failed to initialize signature "
			    "context");
			return;
		}
	} else {
		if (EVP_DigestInit_ex(message->dctx, hash_md, NULL) != 1) {
			dkim_errx(message, "Failed to initialize hash context");
			return;
		}
	}
	for (i--; i >= 0; i--) {
		if (!sephash) {
			if (EVP_DigestSignUpdate(message->dctx,
			    message->headers[i],
			    strlen(message->headers[i])) != 1 ||
			    EVP_DigestSignUpdate(message->dctx, "\r\n",
			    2) <= 0) {
				dkim_errx(message, "Failed to update signature "
				    "context");
				return;
			}
		} else {
			if (EVP_DigestUpdate(message->dctx, message->headers[i],
			    strlen(message->headers[i])) != 1 ||
			    EVP_DigestUpdate(message->dctx, "\r\n", 2) <= 0) {
				dkim_errx(message, "Failed to update digest "
				    "context");
				return;
			}
		}
		if ((tsdomain = dkim_domain_select(message, message->headers[i])) != NULL)
			sdomain = tsdomain;
		/* We're done with the cached header after hashing */
		for (tmp = message->headers[i]; tmp[0] != ':'; tmp++) {
			if (tmp[0] == ' ' || tmp[0] == '\t')
				break;
			tmp[0] = tolower(tmp[0]);
		}
		tmp[0] = '\0';
		if (!dkim_signature_printf(message, "%s%s",
		    message->headers[i + 1] == NULL  ? "" : ":",
		    message->headers[i]))
			return;
	}
	dkim_signature_printf(message, "; d=%s; b=", sdomain);
	if (!dkim_signature_normalize(message))
		return;
	if ((tmp = strdup(message->signature.signature)) == NULL) {
		dkim_err(message, "Can't create DKIM signature");
		return;
	}
	dkim_parse_header(message, tmp, 1);
	if (!sephash) {
		if (EVP_DigestSignUpdate(message->dctx, tmp,
		    strlen(tmp)) != 1) {
			dkim_errx(message, "Failed to update signature "
			    "context");
			return;
		}
	} else {
		if (EVP_DigestUpdate(message->dctx, tmp, strlen(tmp)) != 1) {
			dkim_errx(message, "Failed to update digest context");
			return;
		}
	}
	free(tmp);
	if (!sephash) {
		if (EVP_DigestSignFinal(message->dctx, NULL, &linelen) != 1) {
			dkim_errx(message, "Can't finalize signature context");
			return;
		}
#ifdef HAVE_ED25519
	} else {
		if (EVP_DigestFinal_ex(message->dctx, bdigest,
		    &digestsz) != 1) {
			dkim_errx(message, "Can't finalize hash context");
			return;
		}
		EVP_MD_CTX_reset(message->dctx);
		if (EVP_DigestSignInit(message->dctx, NULL, NULL, NULL,
		    pkey) != 1) {
			dkim_errx(message, "Failed to initialize signature "
			    "context");
			return;
		}
		if (EVP_DigestSign(message->dctx, NULL, &linelen, bdigest,
		    digestsz) != 1) {
			dkim_errx(message, "Failed to finalize signature");
			return;
		}
#endif
	}
	if ((tmp = malloc(linelen)) == NULL) {
		dkim_err(message, "Can't allocate space for signature");
		return;
	}
	if (!sephash) {
		if (EVP_DigestSignFinal(message->dctx, tmp, &linelen) != 1) {
			dkim_errx(message, "Failed to finalize signature");
			return;
		}
#ifdef HAVE_ED25519
	} else {
		if (EVP_DigestSign(message->dctx, tmp, &linelen, bdigest,
		    digestsz) != 1) {
			dkim_errx(message, "Failed to finalize signature");
			return;
		}
#endif
	}
	if ((b = malloc((((linelen + 2) / 3) * 4) + 1)) == NULL) {
		dkim_err(message, "Can't create DKIM signature");
		return;
	}
	EVP_EncodeBlock(b, tmp, linelen);
	free(tmp);
	dkim_signature_printf(message, "%s\r\n", b);
	free(b);
	dkim_signature_normalize(message);
	tmp = message->signature.signature;
	while ((tmp2 = strchr(tmp, '\r')) != NULL) {
		tmp2[0] = '\0';
		osmtpd_filter_dataline(ctx, "%s", tmp);
		tmp = tmp2 + 2;
	}
	tmp = NULL;
	linelen = 0;
	rewind(message->origf);
	while ((i = getline(&tmp, &linelen, message->origf)) != -1) {
		tmp[i - 1] = '\0';
		osmtpd_filter_dataline(ctx, "%s", tmp);
	}
	free(tmp);
}

int
dkim_signature_normalize(struct dkim_message *message)
{
	size_t i;
	size_t linelen;
	size_t checkpoint;
	size_t skip;
	size_t *headerlen = &(message->signature.len);
	int headername = 1;
	char tag = '\0';
	char *sig = message->signature.signature;

	for (linelen = i = 0; sig[i] != '\0'; i++) {
		if (sig[i] == '\r' && sig[i + 1] == '\n') {
			i++;
			checkpoint = 0;
			linelen = 0;
			continue;
		}
		if (sig[i] == '\t')
			linelen = (linelen + 8) & ~7;
		else
			linelen++;
		if (headername) {
			if (sig[i] == ':') {
				headername = 0;
				checkpoint = i;
			}
			continue;
		}
		if (linelen > DKIM_SIGNATURE_LINELEN && checkpoint != 0) {
			for (skip = checkpoint + 1;
			    sig[skip] == ' ' || sig[skip] == '\t';
			    skip++)
				continue;
			skip -= checkpoint + 1;
			if (!dkim_signature_need(message,
			    skip > 3 ? 0 : 3 - skip + 1))
				return 0;
			sig = message->signature.signature;

			memmove(sig + checkpoint + 3,
			    sig + checkpoint + skip,
			    *headerlen - skip - checkpoint + 1);
			sig[checkpoint + 1] = '\r';
			sig[checkpoint + 2] = '\n';
			sig[checkpoint + 3] = '\t';
			linelen = 8;
			*headerlen = *headerlen + 3 - skip;
			i = checkpoint + 3;
			checkpoint = 0;
		}
		if (sig[i] == ';') {
			checkpoint = i;
			tag = '\0';
			continue;
		}
		switch (tag) {
		case 'B':
		case 'b':
		case 'z':
			checkpoint = i;
			break;
		case 'h':
			if (sig[i] == ':')
				checkpoint = i;
			break;
		}
		if (tag == '\0' && sig[i] != ' ' && sig[i] != '\t') {
			if ((tag = sig[i]) == 'b' && sig[i + 1] == 'h' &&
			    sig[i + 2] == '=') {
				tag = 'B';
				linelen += 2;
				i += 2;
			} else
				tag = sig[i];
		}
	}
	return 1;
}

int
dkim_signature_printheader(struct dkim_message *message, const char *header)
{
	size_t i, j, len;
	static char *fmtheader = NULL;
	char *tmp;
	static size_t size = 0;
	int first;

	len = strlen(header);
	if ((len + 3) * 3 < len) {
		errno = EOVERFLOW;
		dkim_err(message, "Can't add z-component to header");
		return 0;
	}
	if ((len + 3) * 3 > size) {
		if ((tmp = reallocarray(fmtheader, 3, len + 3)) == NULL) {
			dkim_err(message, "Can't add z-component to header");
			return 0;
		}
		fmtheader = tmp;
		size = (len + 1) * 3;
	}

	first = message->signature.signature[message->signature.len - 1] == '=';
	for (j = i = 0; header[i] != '\0'; i++, j++) {
		if (i == 0 && header[i] != ' ' && header[i] != '\t' && !first)
			fmtheader[j++] = '|';
		if ((header[i] >= 0x21 && header[i] <= 0x3A) ||
		    (header[i] == 0x3C) ||
		    (header[i] >= 0x3E && header[i] <= 0x7B) ||
		    (header[i] >= 0x7D && header[i] <= 0x7E))
			fmtheader[j] = header[i];
		else {
			fmtheader[j++] = '=';
			(void) sprintf(fmtheader + j, "%02hhX", header[i]);
			j++;
		}
	}
	(void) sprintf(fmtheader + j, "=%02hhX=%02hhX", (unsigned char) '\r',
	    (unsigned char) '\n');

	return dkim_signature_printf(message, "%s", fmtheader);
}

int
dkim_signature_printf(struct dkim_message *message, char *fmt, ...)
{
	struct dkim_signature *sig = &(message->signature);
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	if ((len = vsnprintf(sig->signature + sig->len, sig->size - sig->len,
	    fmt, ap)) >= sig->size - sig->len) {
		va_end(ap);
		if (!dkim_signature_need(message, len + 1))
			return 0;
		va_start(ap, fmt);
		if ((len = vsnprintf(sig->signature + sig->len,
		    sig->size - sig->len, fmt, ap)) >= sig->size - sig->len)
			osmtpd_errx(1, "Miscalculated header size");
	}
	sig->len += len;
	va_end(ap);
	return 1;
}

const char *
dkim_domain_select(struct dkim_message *message, char *from)
{
	char *mdomain0, *mdomain;
	size_t i;

	if ((mdomain = mdomain0 = osmtpd_mheader_from_domain(from)) == NULL) {
		if (errno != EINVAL) {
			dkim_errx(message, "Couldn't parse from header");
			return NULL;
		}
		return NULL;
	}

	while (mdomain != NULL && mdomain[0] != '\0') {
		for (i = 0; i < ndomains; i++) {
			if (strcasecmp(mdomain, domain[i]) == 0) {
				free(mdomain0);
				return domain[i];
			}
		}
		if ((mdomain = strchr(mdomain, '.')) != NULL)
			mdomain++;
	}
	free(mdomain0);
	return NULL;
}

int
dkim_signature_need(struct dkim_message *message, size_t len)
{
	struct dkim_signature *sig = &(message->signature);
	char *tmp;

	if (sig->len + len < sig->size)
		return 1;
	sig->size = (((len + sig->len) / 512) + 1) * 512;
	if ((tmp = realloc(sig->signature, sig->size)) == NULL) {
		dkim_err(message, "No room for signature");
		return 0;
	}
	sig->signature = tmp;
	return 1;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-dkimsign [-tz] [-a signalg] "
	    "[-c canonicalization] \n    [-h headerfields]"
	    "[-x seconds] -d domain -k keyfile -s selector\n");
	exit(1);
}
