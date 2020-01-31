export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

# can be overridden
PREFIX=/usr
PKGVERREL_git=$(shell git describe --long --dirty=+)
PKGVERREL=$(if $(PKGVERREL_git),$(patsubst v%,%,$(PKGVERREL_git)),$(error git describe failed))
PKGVER=$(firstword $(subst -, ,$(PKGVERREL)))
PKGREL=$(PKGVERREL:$(PKGVER)-%=%)

DOCSFILES:=LICENSE README.md TODO.md

all: everything

info:
	@echo PKGVERREL=$(PKGVERREL)
	@echo PKGVER=$(PKGVER)
	@echo PKGREL=$(PKGREL)

GENERATED_SOURCES:=internal/version.go internal/mocks/WgClient.go trust/mock_Evaluator_test.go
generate: $(GENERATED_SOURCES)
#TODO: use go generate for this stuff
internal/version.go: internal/version.go.in .git/HEAD .git/index
	cat $< | sed -e "s/__GIT_VERSION__/$(PKGVERREL)/" > $@.tmp
	mv -f $@.tmp $@
internal/mocks/%.go: internal/%.go
# this assumes mockery is available in the (GO)PATH
	mockery -dir internal/ -output internal/mocks/ -name $*
trust/mock_Evaluator_test.go: trust/trust.go
	mockery -dir trust/ -testonly -inpkg -name Evaluator

fmt: generate
	go fmt ./...
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
	go test ./...
test-go-race: generate
	go test -race ./...
test-stress: test-stress-go test-stress-race
test-stress-go:
	go test -count=1000 ./...
test-stress-race:
	go test -race -count=1000 ./...
coverage.out: generate
	go test -coverpkg=./... -coverprofile=coverage.out ./...
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

.PHONY: all info fmt generate compile run install everything clean
.PHONY: vet lint lint-golint test cover htmlcover
.PHONY: test-go test-go-race test-stress test-stress-go test-stress-race
.PHONY: checkinstall checkinstall-prep checkinstall-clean
# wirelink isn't actually phony, but we can't compute deps for it, so pretend
.PHONY: wirelink
