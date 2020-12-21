#!/bin/bash

set -xeuo pipefail

cd "$(git rev-parse --show-toplevel)"

make clean all checkinstall-cross-amd64 checkinstall-cross-arm64 wg-go-checkinstall-cross-amd64 wg-go-checkinstall-cross-arm64

# filter this to avoid trying to re-deploy debs we already built
# assume wirelink is already new, if it fails, we want to know
newdebs=(
	./packaging/checkinstall/wirelink*.deb
)
for f in ./packaging/wg-go-checkinstall/wireguard-go*.deb ; do
	fb=$(basename "$f")
	if [ ! -f /usr/src/debian/repository/pool/main/w/wireguard-go/$fb ]; then
		newdebs+=("$f")
	fi
done
adddebs release=buster "${newdebs[@]}"

# only install wirelink, wireguard-go is not normally installed
sudo dpkg --install ./packaging/checkinstall/wirelink*$(go env GOARCH).deb
