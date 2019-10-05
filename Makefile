all: wirelink

fmt:
	go fmt ./...
compile:
# first one compiles everything even if the root doesn't need it, but won't make the binary
	go build -v ./...
wirelink: compile
# this one will make the binary, makes for some extra printing
	go build -v
vet: compile
	go vet ./...
test: vet
	go test ./...

run: test wirelink
	sudo ./wirelink

.PHONY: all fmt compile vet test run
