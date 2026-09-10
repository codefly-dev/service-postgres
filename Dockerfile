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
RUN apk add --no-cache --upgrade \
    libcrypto3=3.5.8-r0 \
    libssl3=3.5.8-r0 \
    libuuid=2.42.3-r1 \
    su-exec=0.3-r0 && \
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
