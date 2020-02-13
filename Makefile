export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

# can be overridden
PREFIX=/usr
PKGVERREL_git=$(shell git describe --long --dirty=+)
PKGVERREL=$(if $(PKGVERREL_git),$(patsubst v%,%,$(PKGVERREL_git)),$(error git describe failed))
PKGVER=$(firstword $(subst -, ,$(PKGVERREL)))
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

DOCSFILES:=LICENSE README.md TODO.md

TOOLS:=\
	golang.org/x/tools/cmd/goimports \
	golang.org/x/lint/golint \
	github.com/vektra/mockery/.../ \
	github.com/cweill/gotests/...@develop \
	$(NULL)

all: everything

info:
	@echo PKGVERREL=$(PKGVERREL)
	@echo PKGVER=$(PKGVER)
	@echo PKGREL=$(PKGREL)

install-tools:
	go get $(TOOLS)

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
# for some reason it only puts the exe in if you tell it to build just .
	go build -v .
vet: generate
	go vet ./...
lint: lint-golint
lint-golint: generate
	golint -set_exit_status ./...
test: vet lint test-go test-go-race
test-go: generate
	go test -timeout=10s ./...
test-go-race: generate
	go test -timeout=60s -race ./...
test-stress: test-stress-go test-stress-race
# don't want to run long tests in stress mode,
# could take hours that way
test-stress-go:
	go test -short -timeout=2m -count=1000 ./...
test-stress-race:
	go test -short -timeout=5m -race -count=1000 ./...
coverage.out: generate
	go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
cover: coverage.out
coverage.html: coverage.out
	go tool cover -html=coverage.out -o=coverage.html

run: generate
	go run -exec sudo .

#NOTE: this will delete ./wirelink *sigh
install:
	go install -v

sysinstall: wirelink
	install wirelink $(PREFIX)/bin/
	install -m 644 packaging/wirelink@.service /lib/systemd/system/
	install -m 644 packaging/wl-quick@.service /lib/systemd/system/

checkinstall-clean:
	rm -vf ./packaging/checkinstall/*.deb
	rm -rvf ./packaging/checkinstall/doc-pak/

checkinstall-prep: wirelink
	mkdir -p ./packaging/checkinstall/doc-pak/
	install -m 644 $(DOCSFILES) ./packaging/checkinstall/doc-pak/
checkinstall: checkinstall-prep
# extra quoting on some args to work around checkinstall bugs:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785441
	cd ./packaging/checkinstall && fakeroot checkinstall \
		--type=debian \
		--install=no \
		--fstrans=yes \
		--pkgname=wirelink \
		--pkgversion=$(PKGVER) \
		--pkgrelease=$(PKGREL) \
		--pkglicense=AGPL-3 \
		--pkggroup=net \
		--pkgsource=https://github.com/fastcat/wirelink \
		--maintainer="'Matthew Gabeler-Lee <cheetah@fastcat.org>'" \
		--requires=wireguard-tools \
		--recommends="'wireguard-dkms | wireguard-modules'" \
		--strip=yes \
		--reset-uids=yes \
		--backup=no \
		make -C ../../ sysinstall \
		</dev/null

everything: fmt vet lint compile wirelink test

clean: checkinstall-clean
	rm -vf ./wirelink $(GENERATED_SOURCES) $(patsubst %,%.tmp,$(GENERATED_SOURCES)) ./coverage.out ./coverage.html
#TODO: any way to clean the go cache for just this package?

.PHONY: all info install-tools fmt generate compile run install everything clean
.PHONY: vet lint lint-golint test cover htmlcover
.PHONY: test-go test-go-race test-stress test-stress-go test-stress-race
.PHONY: checkinstall checkinstall-prep checkinstall-clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
