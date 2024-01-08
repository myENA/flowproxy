# ---- Base ----
FROM docker.ena.net/alpine/base AS build-stage
LABEL application=flowproxy-build

COPY . /opt/go/src/gitlab.ena.net/netflow/flowproxy
WORKDIR /opt/go/src/gitlab.ena.net/netflow/flowproxy

RUN apk add --update make libpcap-dev

# build
RUN make build

# deploy
FROM docker.ena.net/alpine/deploy AS deploy
LABEL application=flowproxy

# add some alpine deps
RUN apk add --update --no-cache tzdata

ENV CONSUL_HTTP_ADDR http://cnl01.dev.ena.net:8500

WORKDIR /opt/flowproxy/
# copy executable
COPY --from=build-stage /opt/go/src/gitlab.ena.net/netflow/flowproxy/flowproxy ./
# copy docroot
# COPY --from=build-stage /opt/go/src/gitlab.ena.net/netflow/flowproxy/docroot      ./docroot
