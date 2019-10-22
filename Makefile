export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

# can be overridden
PREFIX=/usr
PKGVER=$(shell git describe | cut -d- -f1)
PKGVERREL=$(shell git describe --long --dirty=+)
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

DOCSFILES:=LICENSE README.md TODO.md

all: everything

fmt:
	go fmt ./...
	goimports -w -l .
compile:
	go build -v ./...
wirelink:
# for some reason it only puts the exe in if you tell it to build just .
	go build -v .
vet:
	go vet ./...
lint: lint-golint lint-gopls
lint-golint:
	golint -set_exit_status ./...
lint-gopls:
# need to group files to gopls check by directory it seems
# unclear if this does anything useful at all
	find -type f -name \*.go -print0 | xargs -0 dirname -z | sort -uz | xargs -P0 -0 -n1 sh -c 'set -x ; gopls check "$$1"/*.go' --
test: vet lint
	go test ./...
coverage.out: test
	go test -coverprofile=coverage.out ./...
cover: coverage.out
coverage.html: coverage.out
	go tool cover -html=coverage.out -o=coverage.html

run:
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
	rm -vf ./wirelink
#TODO: any way to clean the go cache for just this package?

.PHONY: all fmt compile run install everything clean
.PHONY: vet lint lint-golint lint-gopls test cover htmlcover
.PHONY: checkinstall checkinstall-prep checkinstall-clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
