.PHONY: all default install uninstall test build release clean package

PREFIX := /usr/local
DESTDIR :=

MAJORVERSION := 0
MINORVERSION ?= 2
PATCHVERSION := 0
VERSION ?= ${MAJORVERSION}.${MINORVERSION}.${PATCHVERSION}

LDFLAGS := -ldflags '-s -w -X main.version=${VERSION}'
MOD := -mod=vendor
export GO111MODULE=on
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
