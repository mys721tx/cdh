.PHONY: all default install uninstall test build release clean package version

PREFIX := /usr/local
DESTDIR :=

VERSION = $(shell if test -f VERSION; then cat VERSION; else git describe | sed 's/-/./g;s/^v//;'; fi)

LDFLAGS := -ldflags '-s -w -X main.version=${VERSION}'
MOD := -mod=vendor
ARCH := $(shell uname -m)
OS := $(shell uname -o)
GOCC := $(shell go version)
PKGNAME := cdh
BINNAME := cdh
PACKAGE := ${PKGNAME}-${VERSION}-${OS}

ifneq (,$(findstring gccgo,$(GOCC)))
	export GOPATH=$(shell pwd)/.go
	LDFLAGS := -gccgoflags '-s -w'
	MOD :=
endif

default: build

all: | clean package

install:
	install -Dm755 ${BINNAME} $(DESTDIR)$(PREFIX)/bin/${BINNAME}

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/${BINNAME}

test:
	gofmt -l *.go
	@test -z "$$(gofmt -l *.go)" || (echo "Files need to be linted" && false)
	go vet ${MOD}
	go test -v ${MOD}

build:
	go build -v ${LDFLAGS} -o ${BINNAME} ${MOD}

release: | test build
	mkdir ${PACKAGE}
	cp ./${BINNAME} ${PACKAGE}/
	cp ./LICENSE ${PACKAGE}/
	cp ./README.md ${PACKAGE}/

package: release
	tar -czvf ${PACKAGE}.tar.gz ${PACKAGE}
clean:
	rm -rf ${PKGNAME}-*
	rm -f ${BINNAME}

version:
	@echo $(VERSION)
