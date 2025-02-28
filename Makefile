GOPATH:=$(shell go env GOPATH)
export PATH:=$(GOPATH)/bin:$(PATH)

# can be overridden
PREFIX=/usr
PKGVERREL_git=$(shell git describe --long --dirty=+)
PKGVERREL=$(if $(PKGVERREL_git),$(patsubst v%,%,$(PKGVERREL_git)),$(error git describe failed))
PKGVER=$(firstword $(subst -, ,$(PKGVERREL)))
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

DOCSFILES:=LICENSE README.md TODO.md

# tools we need to install in CI
TOOLS:=\
	golang.org/x/vuln/cmd/govulncheck@latest \
	$(NULL)
# tools needed by developers (in addition to the CI ones)
TOOLS_DEV:=\
	github.com/cweill/gotests/gotests@latest \
	github.com/go-delve/delve/cmd/dlv@latest \
	github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
	$(NULL)

all: everything

info:
	@echo PKGVERREL=$(PKGVERREL)
	@echo PKGVER=$(PKGVER)
	@echo PKGREL=$(PKGREL)
	@echo GOPATH=$(GOPATH)
	@echo PATH=$$PATH

install-tools:
	set -xe ; for t in $(TOOLS) ; do go install $$t ; done
install-tools-dev:
	set -xe ; for t in $(TOOLS) $(TOOLS_DEV) ; do go install $$t ; done

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
GENERATED:=\
	$(GENERATED_SOURCES) \
	$(GOGENERATED_SOURCES) \
	$(NULL)
generate: $(GENERATED)
#TODO: use go generate for this step ... requires making a tool that duplicates the version computation above
internal/version.go: internal/version.go.in .git/HEAD .git/index
	cat $< | sed -e "s/__GIT_VERSION__/$(PKGVERREL)/" > $@.tmp
	mv -f $@.tmp $@
$(GOGENERATED_SOURCES):
	go generate ./...

compile: generate
	go tool mage compile
wirelink: generate
	go build -v .
wirelink-cross-%: generate
# build these stripped
	CGO_ENABLED=0 GOARCH=$* go build -ldflags "-s -w" -o $@ -v .
lint: lint-golangci lint-vulncheck
lint-golangci: generate
	golangci-lint run
lint-fix: generate
	golangci-lint run --fix
lint-vulncheck:
	govulncheck -test ./...
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
test-cover: generate
	go test -vet=off -timeout=1m -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
coverage.html: coverage.out
	go tool cover -html=coverage.out -o=coverage.html
test-fuzz: generate
	fgrep -rlZ 'func Fuzz' */ | xargs -0 dirname -z | sort -zu \
		| xargs -0 -t -I_PKG_ go test ./_PKG_ -fuzz=.* -fuzztime=1m

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

everything: fmt lint compile wirelink test

clean: checkinstall-clean
	rm -vf ./wirelink ./wirelink-cross-* $(GENERATED_SOURCES) $(patsubst %,%.tmp,$(GENERATED_SOURCES)) $(GOGENERATED_SOURCES) ./coverage.out ./coverage.html
#TODO: any way to clean the go cache for just this package?

dlv-run-real: compile wirelink
	sudo $(GOPATH)/bin/dlv debug --only-same-user=false --headless --listen=:2345 --log --api-version=2 -- --debug --iface=wg0
.PHONY: dlv-run-real

.PHONY: all info install-tools fmt generate compile run install everything clean
.PHONY: lint test
.PHONY: test-go test-cover test-go-race test-stress test-stress-go test-stress-race
.PHONY: checkinstall checkinstall-prep checkinstall-clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
