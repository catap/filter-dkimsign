LOCALBASE?=	/usr/local/
PROG=		filter-dkimsign
MAN=		filter-dkimsign.8
BINDIR=		${LOCALBASE}/libexec/smtpd/
MANDIR=		${LOCALBASE}/man/man

SRCS+=		main.c mheader.c

.ifdef LIBCRYPTOPC
CRYPT_CFLAGS!=	pkg-config --cflags ${LIBCRYPTOPC}
CRYPT_LDFLAGS!=	pkg-config --libs-only-L ${LIBCRYPTOPC}
CRYPT_LDADD!=	pkg-config --libs-only-l ${LIBCRYPTOPC}
.else
CRYPT_CFLAGS=
CRYPT_LDFLAGS=
CRYPT_LDADD=	-lcrypto
.endif

CFLAGS+=	-I${LOCALBASE}/include -I${.CURDIR}/openbsd-compat 
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	${CRYPT_CFLAGS}
.ifdef HAVE_ED25519
CFLAGS+=	-DHAVE_ED25519
.endif

LDFLAGS+=	-L${LOCALBASE}/lib
LDFLAGS+=	${CRYPT_LDFLAGS}
LDADD+=		${CRYPT_LDADD} -lopensmtpd
DPADD=		${LIBCRYPTO}

bindir:
	${INSTALL} -d ${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
