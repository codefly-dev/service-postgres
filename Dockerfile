# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG POSTGRES_IMAGE=postgres:17.10-alpine3.24@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193
ARG SOURCE_DATE_EPOCH=0

FROM ${POSTGRES_IMAGE} AS pgvector-builder

ARG PGVECTOR_VERSION=0.8.5
ARG PGVECTOR_SHA256=6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44

RUN apk add --no-cache \
    build-base=0.5-r4 \
    clang21=21.1.8-r3 \
    llvm21-dev=21.1.8-r1
ADD --checksum=sha256:${PGVECTOR_SHA256} \
    https://github.com/pgvector/pgvector/archive/refs/tags/v${PGVECTOR_VERSION}.tar.gz \
    /tmp/pgvector.tar.gz
RUN mkdir /tmp/pgvector /tmp/pgvector-install && \
    tar -xzf /tmp/pgvector.tar.gz -C /tmp/pgvector --strip-components=1 && \
    make -C /tmp/pgvector OPTFLAGS="" && \
    make -C /tmp/pgvector DESTDIR=/tmp/pgvector-install install

FROM ${POSTGRES_IMAGE} AS runtime

RUN rm /usr/local/bin/gosu
# --upgrade also upgrades each named package's dependencies, so every package
# this transaction changes is named at its exact version. An unnamed one floats
# with the Alpine index: musl did on 2026-10-26 and moved the image digest.
# musl-utils, zlib and krb5-libs are named for the same reason and for their
# HIGH fixes (CVE-2026-107891 in musl-utils 1.2.6-r2, CVE-2026-85091 in zlib
# 1.3.2-r0, and eighteen HIGHs in krb5-libs 1.22.2-r1 fixed in 1.22.3-r0):
# the pinned base ships the vulnerable revisions and nothing else upgrades them.
RUN apk add --no-cache --upgrade \
    krb5-libs=1.22.3-r0 \
    libcrypto3=3.5.9-r0 \
    libssl3=3.5.9-r0 \
    libuuid=2.42.3-r1 \
    musl=1.2.6-r3 \
    musl-utils=1.2.6-r3 \
    su-exec=0.3-r0 \
    zlib=1.4-r0 && \
    ln -s /sbin/su-exec /usr/local/bin/gosu && \
    rm /var/log/apk.log
COPY --from=pgvector-builder /tmp/pgvector-install/ /

LABEL org.opencontainers.image.source="https://github.com/codefly-dev/service-postgres"

ENV LANG=en_US.utf8
ENV PG_MAJOR=17
ENV PG_VERSION=17.10
ENV PGDATA=/var/lib/postgresql/data

VOLUME ["/var/lib/postgresql/data"]
ENTRYPOINT ["docker-entrypoint.sh"]
STOPSIGNAL SIGINT
EXPOSE 5432
CMD ["postgres"]
