export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

# can be overridden
PREFIX=/usr
PKGVER=$(shell git describe)
PKGVERREL=$(shell git describe --long --dirty=+)
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

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

run:
	go run -exec sudo .

#NOTE: this will delete ./wirelink *sigh
install:
	go install -v

sysinstall: wirelink
	install wirelink $(PREFIX)/bin/
	install -m 644 packaging/wirelink@.service /lib/systemd/system/
	install -m 644 packaging/wl-quick@.service /lib/systemd/system/

checkinstall: wirelink
# extra quoting on some args to work around checkinstall bugs:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785441
	cd packaging/checkinstall && fakeroot checkinstall \
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

clean:
	rm -vf ./wirelink
	rm -vf packaging/checkinstall/*.deb
#TODO: any way to clean the go cache for just this package?

.PHONY: all fmt compile vet lint lint-golint lint-gopls test run install everything clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
