all: build

fmt:
	go fmt ./...
build:
# first one compiles everything even if the root doesn't need it, but won't make the binary
	go build -v ./...
# this one will make the binary, makes for some extra printing
	go build -v
vet: build
	go vet ./...
test: vet
	go test ./...

.PHONY: all fmt build vet test
