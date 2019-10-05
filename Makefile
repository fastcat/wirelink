export PATH:=$(GOPATH)/bin:$(PATH)
export GO111MODULE=on

all: wirelink

fmt:
	go fmt ./...
compile:
# both spread and . to compile everything (not just deps) and make sure it links the exe
	go build -v ./... .
wirelink: compile
vet: compile
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

run: wirelink
	sudo ./wirelink

install: compile
	go install -v

.PHONY: all fmt compile vet lint lint-golint lint-gopls test run install
