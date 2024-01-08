.PHONY: help
help: ## This help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
# name of the binary/exe file
BUILD_NAME ?=flowproxy
BUILD_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD | cut -d "/" -f2)
HASH:= $(shell git rev-parse --short HEAD)

GOTAGS=fpxy
GOCMD=go
GOBUILD=$(GOCMD) build -tags $(GOTAGS) -buildvcs=false
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test -tags $(GOTAGS)
GOGET=$(GOCMD) get -tags $(GOTAGS)
MAKECMD= /usr/bin/make --no-print-directory

# exporting env needs to happen here
GO111MODULE:=on
export GO111MODULE

build: ## Builds the go binary
	@echo "Building ... "
	@$(GOBUILD) -o "${BUILD_NAME}" -ldflags "\
		-X main.BuildBranch=${BUILD_BRANCH} \
		-X main.BuildNumber=${HASH} \
		-X main.BuildName=${BUILD_NAME}"

dist: ## Creates dist.tgz
	@COPYFILE_DISABLE=1 tar -chzf "dist.tgz" ./$(BUILD_NAME)

test: ## Runs go tests
	@$(GOTEST) -v `go list ./... | grep -v /vendor/` >> tests.log
	@cp tests.log ./artifacts

clean: ## Removes unwanted files
	@rm -rf  ${BUILD_NAME} ${BUILD_NAME}.exe tests.log artifacts dist.tgz

# to install golangci-lint
# binary will be $(go env GOPATH)/bin/golangci-lint
# curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.23.6
check: ## Runs different golang checks
	@golangci-lint run -E dupl -E misspell -E gocyclo -E golint -E bodyclose -E unparam -E gocritic -E gofmt -E rowserrcheck --build-tags=$(GOTAGS) --modules-download-mode=readonly ./...

licenses: ## Golang license and dependency checker. Prints list of all dependencies, their URL, license and saves all the license files in /licenses. (see https://github.com/ribice/glice)
	@rm -rf licenses
	@glice -i -f
