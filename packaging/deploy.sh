#!/bin/bash

set -xeuo pipefail

cd "$(git rev-parse --show-toplevel)"

go tool mage clean everything checkinstall:cross amd64 checkinstall:cross arm64

# filter this to avoid trying to re-deploy debs we already built
# assume wirelink is already new, if it fails, we want to know
newdebs=(
	./packaging/checkinstall/wirelink*.deb
)
for distro in bullseye bookworm trixie sid jammy noble ; do
	# run these with no stdin so we do the index export only once
	adddebs release=$distro "${newdebs[@]}" </dev/null
done
# update the indexes
adddebs

# only install wirelink, wireguard-go is not normally installed
sudo dpkg --install ./packaging/checkinstall/wirelink*$(go env GOARCH).deb
