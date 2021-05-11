LOCALBASE?= /usr/local/

PROG=	filter-dkimsign
MAN=	filter-dkimsign.8
BINDIR=	${LOCALBASE}/libexec/opensmtpd/
MANDIR=	${LOCALBASE}/share/man/man8

BINOWN?=	root
BINGRP?=	root
BINPERM?=	755

SRCS+=	main.c mheader.c

CFLAGS+=-I${LOCALBASE}/include
CFLAGS+=-Wall -I${.CURDIR}
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
CFLAGS+=-I${CURDIR} -I${CURDIR}/openbsd-compat/

LDFLAGS+=-L${LOCALBASE}/lib
LDLIBS+=-lcrypto -lopensmtpd

INSTALL?=	install

NEED_RECALLOCARRAY?=	1
NEED_STRLCAT?=		1
NEED_STRTONUM?=		1
NEED_PLEDGE?=		1

.PHONY: all
all: ${PROG}

ifeq (${NEED_RECALLOCARRAY}, 1)
SRCS+=		${CURDIR}/openbsd-compat/recallocarray.c
CFLAGS+=	-DNEED_RECALLOCARRAY=1

recallocarray.o: ${CURDIR}/openbsd-compat/recallocarray.c
	${CC} ${CFLAGS} -c -o recallocarray.o ${CURDIR}/openbsd-compat/recallocarray.c
endif
ifeq (${NEED_STRLCAT}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strlcat.c
CFLAGS+=	-DNEED_STRLCAT=1

strlcat.o: ${CURDIR}/openbsd-compat/strlcat.c
	${CC} ${CFLAGS} -c -o strlcat.o ${CURDIR}/openbsd-compat/strlcat.c
endif
ifeq (${NEED_STRTONUM}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strtonum.c
CFLAGS+=	-DNEED_STRTONUM=1

strtonum.o: ${CURDIR}/openbsd-compat/strtonum.c
	${CC} ${CFLAGS} -c -o strtonum.o ${CURDIR}/openbsd-compat/strtonum.c
endif
ifeq (${NEED_PLEDGE}, 1)
CFLAGS+=	-DNEED_PLEDGE=1
endif

${SRCS:.c=.d}:%.d:%.c
	 ${CC} ${CFLAGS} -MM $< >$@

OBJS=		${notdir ${SRCS:.c=.o}}

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LDLIBS}

.PHONY: clean
clean:
	rm -f *.d *.o ${PROG}

.PHONY: install
install: ${PROG}
	${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${BINPERM} ${PROG} ${BINDIR}
