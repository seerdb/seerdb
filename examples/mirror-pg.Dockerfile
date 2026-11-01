# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PostgreSQL for the Mirror's PostgresBackend, with the orafce extension the
# backend leans on for Oracle-compatible SQL functions (nvl, decode, to_char /
# to_date, add_months, instr, …). The Alpine `postgresql-orafce` package targets
# Alpine's own PostgreSQL major, which differs from the official image's, so
# orafce is built from source against this image's server (PGXS). So is
# pgvector, which Oracle's VECTOR types map onto (#1708), and plpgsql_check,
# which finds the names a PL/SQL unit's body cannot resolve when it is
# created, as Oracle's compiler does (#2129).
#
#   podman build -f examples/mirror-pg.Dockerfile -t mirror-pg .
#   podman run -d --name mirror-pg -p 5433:5432 \
#       -e POSTGRES_USER=pyo -e POSTGRES_PASSWORD=pyo123 -e POSTGRES_DB=mirror \
#       mirror-pg
#
# The PostgresBackend runs `CREATE EXTENSION IF NOT EXISTS orafce` (and `vector`
# and `plpgsql_check` where they are installed) and puts the `oracle` schema on the search_path itself,
# so no further setup is needed.

FROM postgres:16-alpine

ARG ORAFCE_VERSION=VERSION_4_17_1
ARG PGVECTOR_VERSION=v0.8.0
ARG PLPGSQL_CHECK_VERSION=v2.10.11

RUN set -eux; \
    apk add --no-cache --virtual .orafce-build \
        build-base icu-dev openssl-dev curl; \
    curl -fsSL -o /tmp/orafce.tar.gz \
        "https://github.com/orafce/orafce/archive/refs/tags/${ORAFCE_VERSION}.tar.gz"; \
    mkdir -p /tmp/orafce && tar xzf /tmp/orafce.tar.gz -C /tmp/orafce --strip-components=1; \
    cd /tmp/orafce; \
    make USE_PGXS=1 with_llvm=no; \
    make USE_PGXS=1 with_llvm=no install; \
    cd /; rm -rf /tmp/orafce /tmp/orafce.tar.gz; \
    apk del .orafce-build

RUN set -eux; \
    apk add --no-cache --virtual .pgvector-build build-base curl; \
    curl -fsSL -o /tmp/pgvector.tar.gz \
        "https://github.com/pgvector/pgvector/archive/refs/tags/${PGVECTOR_VERSION}.tar.gz"; \
    mkdir -p /tmp/pgvector && tar xzf /tmp/pgvector.tar.gz -C /tmp/pgvector --strip-components=1; \
    cd /tmp/pgvector; \
    make USE_PGXS=1 with_llvm=no OPTFLAGS=""; \
    make USE_PGXS=1 with_llvm=no install; \
    cd /; rm -rf /tmp/pgvector /tmp/pgvector.tar.gz; \
    apk del .pgvector-build

RUN set -eux; \
    apk add --no-cache --virtual .plpgsql-check-build build-base curl; \
    curl -fsSL -o /tmp/plpgsql_check.tar.gz \
        "https://github.com/okbob/plpgsql_check/archive/refs/tags/${PLPGSQL_CHECK_VERSION}.tar.gz"; \
    mkdir -p /tmp/plpgsql_check && tar xzf /tmp/plpgsql_check.tar.gz -C /tmp/plpgsql_check --strip-components=1; \
    cd /tmp/plpgsql_check; \
    make USE_PGXS=1 with_llvm=no; \
    make USE_PGXS=1 with_llvm=no install; \
    cd /; rm -rf /tmp/plpgsql_check /tmp/plpgsql_check.tar.gz; \
    apk del .plpgsql-check-build
