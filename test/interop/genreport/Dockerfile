# genreport from ISC's DNS-Compliance-Testing, built at a fixed commit. Not packaged for Debian or Ubuntu.
#
#   docker build -t dohyo-genreport test/interop/genreport
#   echo "zone server address" | docker run --rm -i --network host dohyo-genreport -f -c -P <port>

ARG DEBIAN=docker.io/library/debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392

FROM ${DEBIAN} AS build

ARG GENREPORT_REPOSITORY=https://gitlab.isc.org/isc-projects/DNS-Compliance-Testing.git
# master as of 2026-11-10 (2022-10-21, "Fix unlinking in nextserver").
ARG GENREPORT_COMMIT=4aea40ba0310de10560ba6deaa2d2e6eebbe8f48

RUN apt-get update \
 && apt-get install -y --no-install-recommends autoconf automake ca-certificates gcc git libc6-dev libssl-dev libtool make pkg-config

# The commit is checked out by its hash, so the source is what was reviewed whatever the branch does later.
# glibc 2.34 and later have res_mkquery in libc, so configure finds no need for libresolv, which still holds ns_get16
# and the other ns_* functions genreport uses.
RUN git clone --quiet "${GENREPORT_REPOSITORY}" /src \
 && git -C /src checkout --quiet --detach "${GENREPORT_COMMIT}" \
 && cd /src \
 && autoreconf -fi \
 && ./configure LIBS=-lresolv \
 && make

FROM ${DEBIAN}

RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/genreport /usr/local/bin/genreport

USER nobody
ENTRYPOINT ["genreport"]
