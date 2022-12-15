LOCALBASE?=	/usr/local/

PROG=		filter-dkimsign
MAN=		filter-dkimsign.8
BINDIR=		${LOCALBASE}/libexec/smtpd/
MANDIR=		${LOCALBASE}/man/man

SRCS+=		main.c mheader.c

.ifdef LIBCRYPTOPC
CRYPT_CFLAGS!=	pkg-config --cflags ${LIBCRYPTOPC}
CRYPT_LDFLAGS_L!=pkg-config --libs-only-L ${LIBCRYPTOPC}
CRYPT_LDFLAGS_libdir!=pkg-config --variable libdir ${LIBCRYPTOPC}
CRYPT_LDFLAGS=	${CRYPT_LDFLAGS_L}
CRYPT_LDFLAGS+=	-Wl,-rpath,${CRYPT_LDFLAGS_libdir}
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

LDFLAGS+=	-L${LOCALBASE}/lib
LDFLAGS+=	${CRYPT_LDFLAGS}
LDADD+=		${CRYPT_LDADD} -lopensmtpd
DPADD=		${LIBCRYPTO}

bindir:
	${INSTALL} -d ${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
