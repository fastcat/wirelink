all: wirelink

fmt:
	go fmt ./...
compile:
# both spread and . to compile everything (not just deps) and make sure it links the exe
	go build -v ./... .
wirelink: compile
vet: compile
	go vet ./...
test: vet
	go test ./...

run: test
	sudo ./wirelink

.PHONY: all fmt compile vet test run
