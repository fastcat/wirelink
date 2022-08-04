#!/bin/bash

set -xeuo pipefail

cd "$(git rev-parse --show-toplevel)"

make clean all checkinstall-cross-amd64 checkinstall-cross-arm64

# filter this to avoid trying to re-deploy debs we already built
# assume wirelink is already new, if it fails, we want to know
newdebs=(
	./packaging/checkinstall/wirelink*.deb
)
adddebs release=bullseye "${newdebs[@]}"

# only install wirelink, wireguard-go is not normally installed
sudo dpkg --install ./packaging/checkinstall/wirelink*$(go env GOARCH).deb
