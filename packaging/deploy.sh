#!/bin/bash

set -xeuo pipefail

cd "$(git rev-parse --show-toplevel)"

make clean
make
make checkinstall-cross-amd64 checkinstall-cross-arm64

adddebs ./packaging/checkinstall/wirelink*.deb

sudo dpkg --install ./packaging/checkinstall/wirelink*$(go env GOARCH).deb
