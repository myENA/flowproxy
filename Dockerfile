# ---- Base ----
FROM golang:alpine AS build-stage
LABEL application=flowproxy-build

COPY . /opt/go/src/github.com/myENA/flowproxy
WORKDIR /opt/go/src/github.com/myENA/flowproxy

RUN apk add --update make libpcap-dev

# build
RUN make build

# deploy
FROM alpine AS deploy
LABEL application=flowproxy

# add some alpine deps
RUN apk add --update --no-cache tzdata

WORKDIR /opt/flowproxy/
# copy executable
COPY --from=build-stage /opt/go/src/github.com/myENA/flowproxy/flowproxy ./