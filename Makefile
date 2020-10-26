GOPATH:=$(shell go env GOPATH)
export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

# can be overridden
PREFIX=/usr
PKGVERREL_git=$(shell git describe --long --dirty=+)
PKGVERREL=$(if $(PKGVERREL_git),$(patsubst v%,%,$(PKGVERREL_git)),$(error git describe failed))
PKGVER=$(firstword $(subst -, ,$(PKGVERREL)))
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

DOCSFILES:=LICENSE README.md TODO.md

# tools needed to build the package
TOOLS:=\
	golang.org/x/tools/cmd/goimports \
	github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
	$(NULL)
# tools needed to develop the package
TOOLS_DEV:=\
	github.com/cweill/gotests/...@develop \
	github.com/go-delve/delve/cmd/dlv \
	$(NULL)

all: everything

info:
	@echo PKGVERREL=$(PKGVERREL)
	@echo PKGVER=$(PKGVER)
	@echo PKGREL=$(PKGREL)
	@echo GOPATH=$(GOPATH)
	@echo PATH=$$PATH

install-tools:
	go get $(TOOLS)
install-tools-dev:
	go get $(TOOLS) $(TOOLS_DEV)

GENERATED_SOURCES:=\
	internal/version.go \
	$(NULL)
GOGENERATED_SOURCES:=\
	internal/mocks/WgClient.go \
	trust/mock_Evaluator_test.go \
	internal/networking/mocks/Environment.go \
	internal/networking/mocks/Interface.go \
	internal/networking/mocks/UDPConn.go \
	$(NULL)
generate: $(GENERATED_SOURCES) $(GOGENERATED_SOURCES)
#TODO: use go generate for this step ... requires making a tool that duplicates the version computation above
internal/version.go: internal/version.go.in .git/HEAD .git/index
	cat $< | sed -e "s/__GIT_VERSION__/$(PKGVERREL)/" > $@.tmp
	mv -f $@.tmp $@
$(GOGENERATED_SOURCES):
	go generate ./...

fmt: generate
	go fmt ./...
	gofmt -s -w $$(find -type f -name \*.go)
	goimports -w -l .
compile: generate
	go build -v ./...
wirelink: generate
	go build -v .
wirelink-cross-%: generate
# build these stripped
	GOARCH=$* go build -ldflags "-s -w" -o $@ -v .
lint: lint-golangci lint-vet
lint-golangci: generate
	golangci-lint run
lint-vet: generate
	go vet ./...
# don't need to run non-race tests if we're gonna run race ones too
test: lint test-go-race
test-go: generate
	go test -vet=off -timeout=20s ./...
test-go-race: generate
	go test -vet=off -timeout=1m -race ./...
test-stress: test-stress-go test-stress-race
# don't want to run long tests in stress mode,
# could take hours that way
test-stress-go:
	go test -vet=off -short -timeout=2m -count=1000 ./...
test-stress-race:
	go test -vet=off -short -timeout=5m -race -count=1000 ./...
coverage.out: generate
	go test -vet=off -timeout=1m -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
cover: coverage.out
coverage.html: coverage.out
	go tool cover -html=coverage.out -o=coverage.html
htmlcover: coverage.html

run: generate
	go run -exec sudo .

#NOTE: this will delete ./wirelink *sigh
install:
	go install -v

sysinstall: wirelink
	install wirelink $(PREFIX)/bin/
	install -m 644 packaging/wirelink@.service /lib/systemd/system/
	install -m 644 packaging/wl-quick@.service /lib/systemd/system/
sysinstall-cross-%: wirelink-cross-%
	install wirelink-cross-$* $(PREFIX)/bin/wirelink
	install -m 644 packaging/wirelink@.service /lib/systemd/system/
	install -m 644 packaging/wl-quick@.service /lib/systemd/system/

checkinstall-clean:
	rm -vf ./packaging/*checkinstall/*.deb
	rm -rvf ./packaging/*checkinstall/doc-pak/

checkinstall-prep-%: wirelink-cross-%
	go mod tidy
	mkdir -p ./packaging/checkinstall/doc-pak/
	install -m 644 $(DOCSFILES) ./packaging/checkinstall/doc-pak/
checkinstall-cross-%: checkinstall-prep-%
# extra quoting on some args to work around checkinstall bugs:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785441
	cd ./packaging/checkinstall && fakeroot checkinstall \
		--type=debian \
		--install=no \
		--fstrans=yes \
		--pkgarch=$* \
		--pkgname=wirelink \
		--pkgversion=$(PKGVER) \
		--pkgrelease=$(PKGREL) \
		--pkglicense=AGPL-3 \
		--pkggroup=net \
		--pkgsource=https://github.com/fastcat/wirelink \
		--maintainer="'Matthew Gabeler-Lee <cheetah@fastcat.org>'" \
		--requires=wireguard-tools \
		--recommends="'wireguard-dkms | wireguard-modules'" \
		--reset-uids=yes \
		--backup=no \
		$(MAKE) -C ../../ sysinstall-cross-$* \
		</dev/null

# rules for building wireguard-go, for crostini
WG_GO_DIR_a:=$(shell go env GOPATH)/src/golang.zx2c4.com/wireguard
WG_GO_DIR_b:=$(HOME)/src/wireguard
ifneq ($(wildcard $(WG_GO_DIR_a)/Makefile),)
WG_GO_DIR:=$(WG_GO_DIR_a)
else ifneq ($(wildcard $(WG_GO_DIR_b)/Makefile),)
WG_GO_DIR:=$(WG_GO_DIR_b)
else
WG_GO_DIR=$(error Cannot find wireguard-go sources)
endif
WG_GO_DOCSFILES:=README.md COPYING
WG_GO_PKGVERREL_git=$(shell git -C "$(WG_GO_DIR)" describe --long --dirty=+)
WG_GO_PKGVERREL=$(if $(WG_GO_PKGVERREL_git),$(patsubst v%,%,$(WG_GO_PKGVERREL_git)),$(error git describe failed))
WG_GO_PKGVER=$(firstword $(subst -, ,$(WG_GO_PKGVERREL)))
WG_GO_PKGREL=$(WG_GO_PKGVERREL:$(WG_GO_PKGVER)-%=%)
wg-go-prep:
	git -C "$(WG_GO_DIR)" pull
	git -C "$(WG_GO_DIR)" clean -fdx
.PHONY: wg-go-prep
wg-go-cross-%: wg-go-prep
# TODO: would like to ensure we only do generate-version once, but the wg
# Makefile doesn't support that
# TODO: Want to pass -ldflags="-s -w", but can't, because
# https://github.com/golang/go/issues/26849
# -s benefits more than -w, so start there
	GOARCH=$* GOFLAGS="-ldflags=-s" $(MAKE) -C "$(WG_GO_DIR)" clean generate-version-and-build
wg-go-checkinstall-prep-%: wg-go-cross-%
	mkdir -p ./packaging/wg-go-checkinstall/doc-pak
	install -m 644 $(patsubst %,$(WG_GO_DIR)/%,$(WG_GO_DOCSFILES)) ./packaging/wg-go-checkinstall/doc-pak/
wg-go-checkinstall-cross-%: wg-go-checkinstall-prep-%
	cd ./packaging/wg-go-checkinstall && fakeroot checkinstall \
		--type=debian \
		--install=no \
		--fstrans=yes \
		--pkgarch=$* \
		--pkgname=wireguard-go \
		--pkgversion=$(WG_GO_PKGVER) \
		--pkgrelease=$(WG_GO_PKGREL) \
		--pkglicense=MIT \
		--pkggroup=net \
		--pkgsource=https://git.zx2c4.com/wireguard-go \
		--maintainer="'Matthew Gabeler-Lee <cheetah@fastcat.org>'" \
		--recommends="'wireguard-tools'" \
		--provides="'wireguard-modules (= $(WG_GO_PKGVERREL))'" \
		--reset-uids=yes \
		--backup=no \
		$(MAKE) -C "$(WG_GO_DIR)" install \
		</dev/null

everything: fmt lint compile wirelink test

clean: checkinstall-clean
	rm -vf ./wirelink ./wirelink-cross-* $(GENERATED_SOURCES) $(patsubst %,%.tmp,$(GENERATED_SOURCES)) $(GOGENERATED_SOURCES) ./coverage.out ./coverage.html
#TODO: any way to clean the go cache for just this package?

dlv-run-real: compile wirelink
	sudo $(GOPATH)/bin/dlv debug --only-same-user=false --headless --listen=:2345 --log --api-version=2 -- --debug --iface=wg0
.PHONY: dlv-run-real

.PHONY: all info install-tools fmt generate compile run install everything clean
.PHONY: lint test cover htmlcover
.PHONY: test-go test-go-race test-stress test-stress-go test-stress-race
.PHONY: checkinstall checkinstall-prep checkinstall-clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
